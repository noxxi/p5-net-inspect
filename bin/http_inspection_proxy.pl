#!/usr/bin/perl

=pod

TODO:
- work transparently, e.g. with iptables REDIRECT rules, instead of
  parsing Host header
- more and useful filters
- ...

=cut

use strict;
use warnings;
use Net::Inspect::Debug qw($DEBUG debug %TRACE);
use Net::Inspect::L7::HTTP;
use Net::Inspect::L7::HTTP::Request::InspectChain;
use Getopt::Long qw(:config posix_default bundling);
use IO::Socket::INET6;
#use Net::PcapWriter; - on Demand
use AnyEvent;

sub usage {
    print STDERR <<USAGE;

Proxy to forward after inspecting/modifying request and response.
Current setup just adds 'X-Custom-Header' to response header, but removes
unchunking and compression.

$0 Options* [ip:port]+
Options:
  -h|--help        show usage
  -d|--debug       debug mode
  -T|--trace T     enable traces
  -P|--pcapdir D   save connections as pcap files into D
  --filter F       add named filter/modifier, can be used multiple times

USAGE
    exit(2);
}

my (@filter,$pcapdir);
GetOptions(
    'd|debug' => \$DEBUG,
    'T|trace=s' => sub { $TRACE{$_} = 1 for split(m/,/,$_[1]) },
    'h|help' => sub { usage() },
    'P|pcapdir=s' => \$pcapdir,
    'filter=s' => \@filter,
);
my @addr = @ARGV or usage("no listener");
die "pcap directory not writeable " if $pcapdir and not -d $pcapdir && -w _;
require Net::PcapWriter if $pcapdir;

main();
############################################################################
# Connection object
# derived from Net::Inspect::L7::HTTP
# just pipes all input into conn->in(...)
############################################################################

package myHTTPConn;
use base 'Net::Inspect::L7::HTTP';
use Hash::Util 'lock_keys';
use Net::Inspect::Debug;
use Scalar::Util 'weaken';
use fields (
    'fds',         # array of fos: 0 for client, 1 for server connection
    'upstream',    # current upstream host
    'spool',       # any data which cannot be processed yet?
    'pcapw',       # Net::PcapWriter
    'didit',       # timestamp for last read|write
);


# active connections, inserted at new_connection, removed in idlet
my @active_connections;

my $idlet = AnyEvent->timer( after => 5, interval => 5, cb => sub {
	@active_connections = grep { $_ } @active_connections
	    or return;
	debug("check timeouts for %d conn",+@active_connections);
	my $now = AnyEvent->now;
	for (@active_connections) {
	    $_ or next;
	    $_->{didit} + 30 > $now and return;
	    $_->Close
	}
    }
);

sub DESTROY { shift->xdebug("connection done"); }
sub new_connection {
    my ($self,$fd) = @_;
    my $obj = $self->SUPER::new_connection({
	daddr => $fd->sockhost,
	dport => $fd->sockport,
	saddr => $fd->peerhost,
	sport => $fd->peerport,
    });
    $obj->newfo(0,$fd);
    readmask($obj,0,1);
    $obj->{didit} = AnyEvent->now;

    if ( $pcapdir ) {
	open( my $fh,'>', sprintf("%s/%d.%d.pcap",$pcapdir,$$,$obj->{connid}))
	    or die "cannot open pcap file: $!";
	$fh->autoflush;
	my $w = Net::PcapWriter->new($fh);
	my $c = $w->tcp_conn( $fd->sockhost, $fd->sockport,
	    $fd->peerhost, $fd->peerport );
	$obj->{pcapw} = [$c,$w],
    }


    push @active_connections,$obj;
    weaken($active_connections[-1]);

    return $obj;
}

sub fatal {
    my ($self,$reason) = @_;
    $reason = "$$.$self->{connid} $reason";
    warn "[fatal] $reason\n";
    $self->Close;
}

sub in {
    my $self = shift;
    return $self->SUPER::in(@_) if ! $self->{pcapw};
    my ($dir,$data,$eof,$time) = @_;
    if ( defined ( my $bytes = eval { $self->SUPER::in(@_) } )) {
	$self->{pcapw}[0]->write($dir,substr($data,0,$bytes));
	return $bytes;
    } else {
	# save final data
	$self->{pcapw}[0]->write($dir,$data);
	die $@ if $@;
	return;
    }
}

sub readmask {
    my ($self,$dir,$mask) = @_;
    my $fo = $self->{fds}[$dir] or return;
    if ( $mask ) {
	$fo->{status} & 0b100 and return 0; # read shutdown already
	$fo->{rwatch} and return 1;
	$fo->{rsub} ||= sub { _read($self,$dir) };
	$fo->{rwatch} = AnyEvent->io(
	    fh => $fo->{fd},
	    poll => 'r',
	    cb => $fo->{rsub}
	);
    } else {
	undef $fo->{rwatch};
    }
    return 1;
}

sub _read {
    my ($self,$dir) = @_;
    my $fo = $self->{fds}[$dir] or return;
    my $n = sysread($fo->{fd},$fo->{rbuf},2**15,length($fo->{rbuf}));
    if ( ! defined $n ) {
	$self->fatal("read($dir) failed: $!");
	return;
    }
    if ( ! $n ) {
	# eof
	$self->xdebug("read shutdown $dir");
	undef $fo->{rwatch};
	undef $fo->{rsub};
	$fo->{status} |= 0b100; # read-shutdown
	shutdown($fo->{fd},0);
	$self->_closeIfDone and return;
    }

    $self->{didit} = AnyEvent->now;
    if ( my $bytes = $self->in($dir,$fo->{rbuf},!$n,AnyEvent->now)) {
	substr($fo->{rbuf},0,$bytes,'');
    }
    my $odir = $dir?0:1;
    if ( my $ofo = $self->{fds}[$odir] ) {
	if ( $ofo->{wbuf} ne '' ) {
	    _write($self,$odir);
	    # disable read until all data are written to the other side
	    if ( $ofo->{wbuf} ne '' ) {
		_writemask($self,$odir,1);
		undef $fo->{rwatch};
		return;
	    }
	}

	# wbuf empty, if eof close writer too
	if ( ! $n ) {
	    $self->xdebug("write shutdown $odir");
	    undef $fo->{wwatch};
	    undef $fo->{wsub};
	    $ofo->{status} |= 0b010; # write shutdown
	    shutdown($ofo->{fd},1);
	    $self->_closeIfDone and return;
	}
    }
}

sub _closeIfDone {
    my $self = shift;
    my $fds = $self->{fds} or return 1;
    if ( ! $fds->[0] || $fds->[0]{status} & 0b110 == 0b110
	and ! $fds->[1] || $fds->[1]{status} & 0b110 == 0b110 ) {
	$self->Close;
	return 1;
    }
    return;
}

sub _writemask {
    my ($self,$dir,$mask) = @_;
    my $fo = $self->{fds}[$dir] or return;
    if ( $mask ) {
	$fo->{wwatch} and return;
	$fo->{wsub} ||= sub { $self->_write($dir) };
	$fo->{wwatch} = AnyEvent->io(
	    fh => $fo->{fd},
	    poll => 'w',
	    cb => $fo->{wsub}
	);
    } else {
	undef $fo->{wwatch};
    }
}

sub Send {
    my ($self,$dir,$data) = @_;
    my $fo = $self->{fds}[$dir] or return; # socket down
    $fo->{wbuf} .= $data;
    _write($self,$dir);
}

sub Close {
    my $self = shift;
    $self->xdebug("closing");
    for (@{$self->{fds}}) {
	$_->{wwatch} = $_->{rwatch} = $_->{wsub} = $_->{rsub} = undef;
	close($_->{fd}) if $_->{fd};
	$_->{fd} = undef;
    }
    undef $self->{fds};
}

sub _write {
    my ($self,$dir) = @_;

    my $fo = $self->{fds}[$dir] or return;
    my $n = syswrite($fo->{fd},$fo->{wbuf});
    if ( ! defined $n ) {
	$self->fatal("write($dir) failed: $!");
	return;
    }

    $self->{didit} = AnyEvent->now;

    substr($fo->{wbuf},0,$n,'');
    if ( $fo->{wbuf} eq '' ) {
	# nothing more to write
	$self->xdebug("all written to $dir");
	undef $fo->{wwatch};
	# enable read again
	if ( ! readmask($self,$dir?0:1,1) ) {
	    # already shutdown - propagate
	    shutdown($fo->{fd},1);
	    $fo->{status} |= 0b010; # write shutdown
	    $self->xdebug("write shutdown $dir");
	    undef $fo->{wsub};
	    $self->_closeIfDone and return;
	}
    }
}


sub newfo {
    my ($self,$dir,$fd,$status) = @_;
    my %fo = (
	fd => $fd,
	# read shutdown|write shutdown|connected
	status => defined($status) ? $status : 0b001, # connected
	rbuf => '', rsub => undef, rwatch => undef,
	wbuf => '', wsub => undef, wwatch => undef,
    );
    lock_keys(%fo);
    $self->{fds}[$dir] = \%fo
}

sub dump_state {
    my $self = shift;
    if ( my $fds = $self->{fds} ) {
	my @st;
	for( my $i=0;$i<@$fds;$i++) {
	    push @st, sprintf("%d=%03b",$i,$fds->[$i]{status} || 0);
	}
	$self->xdebug("status @st");
    };
    $self->SUPER::dump_state;
}


############################################################################
# Request
############################################################################
package myHTTPRequest;
use base 'Net::Inspect::L7::HTTP::Request::InspectChain';
use fields qw(chunked);
use Net::Inspect::Debug qw(debug $DEBUG);
use AnyEvent::Socket qw(tcp_connect format_address);


sub in_request_header {
    my $self = shift;

    # if there is a request still open spool call
    if ( my $spool = $self->{conn}{spool} ) {
	push @$spool,['in_request_header',@_];
	# disable read - other calls might still be spooled because
	# they origin from the same packet (post data, pipelining..)
	$self->readmask(0,0);
	return 1;
    }

    my ($hdr,$time) = @_;
    my ($method) = $hdr =~m{^(\w+)};
    if ( $method !~ m{^(?:GET|POST|PUT|DELETE|TRACE|OPTIONS|CONNECT)$} ) {
	$self->fatal("cannot handle method $method");
	return 1;
    }

    $hdr =~s{^Proxy-Connection:}{Connection:}im; #
    $self->add_hooks({
	name => 'fwd-data',
	request_header => \&_connect_upstream,
	request_body => sub {
	    my ($self,$data,$eof,$time) = @_;
	    if ( $$data ne '' ) {
		$self->{conn}->Send(1,$$data);
		$$data = '';
	    }
	    return '';
	},
	response_header => sub {
	    my ($self,$hdr,$time) = @_;
	    $self->{conn}->Send(0,$$hdr);
	    return 0;
	},
	response_body => sub {
	    my ($self,$data,$eof,$time) = @_;
	    $self->{conn}->Send(0,$$data) if $$data ne '';
	    $$data = '';
	    return '';
	},
	chunk_header => sub {
	    my ($self,$hdr,$time) = @_;
	    return if $$hdr eq '';
	    $self->{conn}->Send(0, $self->{chunked}++ ? "\r\n$$hdr" : $$hdr );
	    return 1;
	},
	chunk_trailer => sub {
	    my ($self,$trailer,$time) = @_;
	    return if $$trailer eq '';
	    $self->{conn}->Send(0, $$trailer );
	    return 1;
	},
    });

    $self->{conn}{spool} ||= [];
    return $self->SUPER::in_request_header($hdr,$time);
}

sub in_request_body {
    my $self = shift;
    my $conn = $self->{conn};

    # if there is a request still open spool call
    # at least in_request_header must have been spooled
    my $spool = $conn->{spool};
    if ( $spool && @$spool ) {
	$self->xdebug("spooling request body");
	push @$spool,['in_request_body',@_];
	return 1;

    # post data but not yet connected
    } elsif ( ! $conn->{fds}[1] ) {
	#$self->xdebug("spooling postdata because not connected yet");
	$conn->readmask(0,0);
	$conn->{spool} ||= [];
	push @$spool,['in_request_body',@_];
	return 1;
    }

    return $self->SUPER::in_request_body(@_);
}

sub _call_spooled {
    my ($self,$what) = @_;
    my $spool = $self->{conn}{spool} or return;
    $self->{conn}{spool} = undef;

    while ( @$spool and ! $self->{conn}{spool} ) {
	my ($method,@arg) = @{ shift(@$spool) };
	if ( ! $what or $what->{$method} ) {
	    $self->$method(@arg);
	} else {
	    unshift @$spool,[$method,@arg];
	    last;
	}
    }

    # put unfinished requests back into spool
    unshift @{ $self->{conn}{spool} }, @$spool if @$spool;

    # enable read again if nothing in spool
    $self->{conn}->readmask(0,1) if ! $self->{conn}{spool};
}

sub in_response_body {
    my ($self,$data,$eof,$time) = @_;
    my $rv = $self->SUPER::in_response_body($data,$eof,$time);
    if ( $eof ) {
	$self->xdebug("got eof in response");
	my $rphdr = $self->response_header;
	if ( ! $rphdr->header('Content-length') and
	    ($rphdr->header('Transfer-Encoding')||'') !~m{\bchunked\b} ) {
	    # no content-length given etc, probably because of decompression
	    # need to close connection at response end to signal end of
	    # response
	    $self->xdebug("closing connection");
	    $self->{conn}->Close;
	    return $rv;
	} else {
	    #$self->xdebug("response header: ".$rphdr->as_string);
	}

	# any more spooled requests (pipelining)?
	_call_spooled($self);
    }
    return $rv
}

sub in_data {
    my ($self,$dir,$data,$eof,$time) = @_;
    # forward data to other side
    $self->xdebug("%s bytes from %s to %s",length($data),$dir,$dir?0:1);
    $self->{conn}->Send($dir?0:1,$data) if $data ne '';
    return length($data);
}

sub _connect_upstream {
    my ($self,$hdr,$time) = @_;
    my $req = $self->request_header;
    my $uri = $req->uri;

    my $hdr_changed = 0;
    my ($proto,$host,$port,$page);
    if ( $req->method eq 'CONNECT' ) {
	($host,$port) = $uri =~m{^(.*?)(?:\:(\d+))?$};
	$port ||= 443;
	$host =~s{^\[(.*)\]$}{$1};
	$proto = 'https';
	$page = '';
	# dont' forward anything, but don't change header :)
	$hdr = \( '' );
    } else {
	($proto,$host,$port,$page) = ($1,$2,$3||80,$4)
	    if $uri =~m{^(?:(\w+)://([^/\s]+?)(?::(\d+))?)?(/.*|$)};
	($proto,$host,$port) = ('http',$2,$3||80)
	    if ! $proto and
	    $req->header('Host') =~m{^(\S+?)(?:(\d+))?$};
	$proto or return $self->fatal('bad request: '.$$hdr),undef;
	return $self->fatal("bad proto: $proto"),undef
	    if $proto ne 'http';

	# make method://host/page to /page
	$hdr_changed = 1 if $$hdr =~s{\A(\w+[ \t]+)(\w+://[^/]+)}{$1};
    }

    $self->xdebug("new request $proto://$host:$port$page");

    $host =~s{^\[(.*)\]$}{$1}; # ipv6
    if ( $self->{conn}{upstream} and
	$self->{conn}{upstream} ne "$host.$port") {
	$self->xdebug("upstream host changed from $self->{conn}{upstream} to $host.$port");
	undef $self->{conn}{upstream};
	undef $self->{conn}{fds}[1];
    }

    # check if we have the connection still open,
    # otherwise connect
    if ( ! $self->{conn}{fds}[1] ) {
	$self->xdebug("connecting to $host.$port");
	# async dns lookup + connect
	myDNS::lookup($host, sub {
	    $self->{conn} or return; # already closed
	    if ( my $addr = shift ) {
		tcp_connect($addr,$port, sub {
		    if ( my $fd = shift ) {
			if ( $self->{conn} ) {
			    $self->{conn}{upstream} = "$host.$port";
			    $self->{conn}->newfo(1,$fd);
			    $self->{conn}->readmask(1,1);
			    $self->xdebug("connect done");
			    _connect_upstream_connected($self,$hdr,$time);
			}
		    } else {
			myDNS::uncache($host,$addr);
			$self->fatal("connect to $host.$port failed: $!");
			return;
		    }
		});
	    } else {
		$self->fatal(
		    "connect to $host.$port failed: no such host (DNS)");
	    }
	});
    } else {
	_connect_upstream_connected($self,$hdr,$time);
    }
    return $hdr_changed;
}

sub _connect_upstream_connected {
    my ($self,$hdr,$time) = @_;

    if ( $DEBUG ) {
	my $cfd = $self->{conn}{fds}[0]{fd};
	my $sfd = $self->{conn}{fds}[1]{fd};
	my $gethost = sub {
	    my ($s,$h) = AnyEvent::Socket::unpack_sockaddr(shift || return 'undef');
	    return format_address($h).".$s";
	};
	$self->xdebug( "request from %s | %s to %s | %s",
	    $gethost->(getpeername($cfd)),
	    $gethost->(getsockname($cfd)),
	    $gethost->(getsockname($sfd)),
	    $gethost->(getpeername($sfd)),
	);
    }

    if ( $$hdr ne '' ) {
	$self->{conn}->Send(1,$$hdr);
    } else {
	# successful Upgrade, CONNECT.. - send OK to client
	# fake that it came from server so that the state gets
	# maintained in Net::Inspect::L7::HTTP
	$self->{conn}->in(1,"HTTP/1.0 200 OK\r\n\r\n",0,$time);
    }

    # any more spooled request bodys?
    _call_spooled($self,{ in_request_body => 1 });

    return 0; # not modified
}

sub fatal {
    my ($self,$reason) = @_;
    my $conn = $self->{conn};
    if ( $conn ) {
	my $reqid = $self->{conn}{meta} && $self->{conn}{meta}{reqid} // '';
	$reason = "$$.$self->{conn}{connid}.$reqid $reason";
	$self->{conn}->Close;
    }
    warn "[fatal] $reason\n";
}

############################################################################
# DNS cache
############################################################################
package myDNS;
use AnyEvent::DNS;
use Socket qw(AF_INET AF_INET6 inet_pton);

my %cache;
sub uncache {
    my ($host,$addr) = @_;
    my $e = $cache{lc($host)} or return;
    @$e = grep { $_ ne $addr } @$e;
    delete $cache{lc($host)} if !@$e;
}

sub lookup {
    my ($host,$cb) = @_;
    $host = lc($host);

    if ( my $e = $cache{$host} ) {
	return $cb->(@$e);
    } elsif ( inet_pton(AF_INET,$host) || inet_pton(AF_INET6,$host) ) {
	return $cb->($host);
    }

    AnyEvent::DNS::a($host,sub {
	if ( @_ ) {
	    $cache{$host} = [ @_ ];
	    return $cb->(@_);
	}

	# try AAAA
	AnyEvent::DNS::aaaa($host,sub {
	    $cache{$host} = [ @_ ] if @_;
	    return $cb->(@_);
	});
    });
}

############################################################################
# MAIN
############################################################################
package main;
sub main {
    # create connection fabric, attach request handling
    my $req  = myHTTPRequest->new;
    my $conn = myHTTPConn->new($req);
    $req->add_hooks('unchunk','uncompress_te','uncompress_ce');

    # hooks adds custom header to each response
    $req->add_hooks({
	name => 'custom-header',
	response_header => sub {
	    my ($self,$hdr) = @_;
	    my $rsp = $self->response_header;
	    $rsp->header( 'X-Custom-Header' => 'abcde' );
	    $$hdr = $rsp->as_string;
	    return 1;
	},
    });

    # create listeners
    my @listen;
    for my $addr (@addr) {
	my $fd = IO::Socket::INET6->new(
	    LocalAddr => $addr,
	    Listen    => 10,
	    Reuse     => 1,
	) or die "cannot listen to $addr: $!";
	push @listen, AnyEvent->io(
	    fh => $fd,
	    poll => 'r',
	    cb => sub {
		my $cl = $fd->accept or return;
		$conn->new_connection($cl);
	    }
	);
    }

    my $sw = AnyEvent->signal( signal => 'USR1', cb => sub {
	debug("-------- active connections -------------");
	for(@active_connections) {
	    $_ or next;
	    $_->dump_state;
	}
	debug("-----------------------------------------");
    });


    # Mainloop
    my $loopvar = AnyEvent->condvar;
    $loopvar->recv;
    exit;
}
