#!/usr/bin/perl
use strict;
use warnings;
use Socket;
use Getopt::Long qw(:config posix_default bundling);
use Net::Pcap qw(:functions);

use Net::Inspect::Debug qw(:DEFAULT %TRACE $DEBUG);
use Net::Inspect::L2::Pcap;
use Net::Inspect::L3::IP;
use Net::Inspect::L4::TCP;
use Net::Inspect::L5::GuessProtocol;
use Net::Inspect::L7::HTTP;
use Net::Inspect::L5::NoData;
use Net::Inspect::L5::Unknown;
use Net::Inspect::L7::HTTP::Request::InspectChain;

############################################################################
# Options
############################################################################
my ($infile,$dev,$nopromisc,@trace,$outdir);
my $uncompress = 1;
my $unchunk = 1;
GetOptions(
    'r=s' => \$infile,
    'i=s' => \$dev,
    'p'   => \$nopromisc,
    'h|help' => sub { usage() },
    'd|debug' => \$DEBUG,
    'T|trace=s' => sub { push @trace,split(m/,/,$_[1]) },
    'D|dir=s' => \$outdir,
    'uncompress!' => \$uncompress,
    'unchunk!' => \$unchunk,
) or usage();
usage('only interface or file can be set') if $infile and $dev;
$infile ||= '/dev/stdin' if ! $dev;
my $pcapfilter = join(' ',@ARGV);
$TRACE{$_} = 1 for(@trace);
die "cannot write to $outdir: $!" if $outdir and ! -w $outdir || ! -d _;

sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<USAGE;

reads data from pcap file or device and analyzes it.
Right now it will collect tcp streams which look like http and extract
requests and responses. Transfer encoding of chunked and content encoding
of gzip/deflate will be transparently removed.

Usage: $0 [options] [pcap-filter]
Options:
    -h|--help        this help
    -r file.pcap     read pcap from file
    -i dev           read pcap from dev
    -p               do net set dev into promisc mode
    -D dir           extract data into dir, right now only for http requests
		     and responses
    -T trace         trace messages are enabled in the modules, option can
		     be given multiple times, trace is last part of module name,
		     e.g. tcp, rawip, http,...
		     To enable all specify '*'
    -d|--debug       various debug messages are shown
USAGE
    exit(2);
}


# open pcap
############################################################################
my $err;
my $pcap = $infile
    ? pcap_open_offline($infile,\$err)
    : pcap_open_live($dev,2**16,!$nopromisc,0,\$err);
$pcap or die $err;
if ( $pcapfilter ) {
    pcap_compile($pcap, \(my $compiled), $pcapfilter,0,0xffffffff) == 0
	or die "bad filter '$pcapfilter'";
    pcap_setfilter($pcap,$compiled) == 0 or die;
}

my $fcache = myFileCache->new(128);

# parse hierarchy
############################################################################

my $guess = Net::Inspect::L5::GuessProtocol->new;
my $tcp = Net::Inspect::L4::TCP->new($guess);
my $raw = Net::Inspect::L3::IP->new($tcp);
my $pc  = Net::Inspect::L2::Pcap->new($pcap,$raw);

my $http_request = myHTTPRequest->new($outdir);
my %opt = ( '-original-header-prefix' => 'X-Original-' );
$http_request->add_hooks( %opt,'unchunk') if $unchunk || $uncompress;
$http_request->add_hooks( %opt,'uncompress_te','uncompress_ce') if $uncompress;
my $http_conn = myHTTPConn->new($http_request);
my $null = Net::Inspect::L5::NoData->new();
my $fallback = Net::Inspect::L5::Unknown->new();

$guess->attach($http_conn);
$guess->attach($null);
$guess->attach($fallback);
#$fallback->attach( HandleRestPort80->new($outdir) );


# Mainloop
############################################################################
pcap_loop($pcap,-1,sub {
    my (undef,$hdr,$data) = @_;
    return $pc->pktin($data,$hdr);
},undef);



package myHTTPConn;
use base 'Net::Inspect::L7::HTTP';
use fields qw(flowid reqnum);
use Net::Inspect::Debug;

my $flowid;
sub new_connection {
    my ($self,$meta) = @_;
    my $obj = $self->SUPER::new_connection($meta);
    $obj->{flowid} = ++( $flowid ||= 0 );
    $obj->{reqnum} = 0;
    return $obj;
}

sub new_request {
    my ($self,@arg) = @_;
    return $self->SUPER::new_request(@arg,$self,$self->{flowid},
	++$self->{reqnum});
}

sub fatal {
    my ($self,$reason) = @_;
    trace( sprintf("%05d %s",$self->{flowid},$reason));
}


package myHTTPRequest;
use base 'Net::Inspect::L7::HTTP::Request::InspectChain';
use fields qw(outdir flowid flowreqid fn chunked);
use Net::Inspect::Debug;

sub new {
    my ($class,$dir) = @_;
    my $self = $class->SUPER::new;
    $self->{outdir} = $dir || ref($class) && $class->{outdir};
    return $self;
}
sub new_request {
    my ($self,$meta,$conn,$flowid,$flowreqid) = @_;
    my $obj = $self->SUPER::new_request($meta,$conn);
    $obj->{flowid} = $flowid;
    $obj->{flowreqid}  = $flowreqid;
    $obj->{fn} = [];
    return $obj;
}

sub DESTROY {
    my $fn = shift->{fn} or return;
    $fcache->del($_) for (@$fn);
}

sub in_request_header {
    my ($self,$hdr,$time) = @_;
    if ( $self->{outdir} ) {
	for my $dir (0,1) {
	    my $fname = sprintf("%s/%05d.%04d.%02d-%s.%s-%s.%s-%d",
		$self->{outdir},
		$self->{flowid},
		$self->{flowreqid},
		$self->{meta}{time},
		$self->{meta}{saddr}, $self->{meta}{sport},
		$self->{meta}{daddr}, $self->{meta}{dport},
		$dir
	    );
	    $self->{fn}[$dir] = $fname;
	    $fcache->add($fname) or die "cannot create $fname: $!";
	}
	my $wfh = sub {
	    my ($self,$dir,$hdr) = @_;
	    my $fh = $fcache->get($self->{fn}[$dir]);
	    print $fh $hdr;
	    return 0;
	};
	my $wfb = sub {
	    my ($self,$dir,$dr) = @_;
	    my $fh = $fcache->get($self->{fn}[$dir]);
	    print $fh $$dr;
	    $$dr = '';
	    return '';
	};

	$self->add_hooks({
	    request_header  => sub { $wfh->($_[0],0,${$_[1]}) },
	    response_header => sub { $wfh->($_[0],1,${$_[1]}) },
	    request_body    => sub { $wfb->($_[0],0,$_[1]) },
	    response_body   => sub { $wfb->($_[0],1,$_[1]) },
	    chunk_header    => sub {
		my ($self,$hdr) = @_;
		my $fh = $fcache->get($self->{fn}[1]);
		print $fh "\r\n" if $self->{chunked}++;
		print $fh $$hdr;
		$$hdr = '';
	    },
	    chunk_trailer   => sub {
		my ($self,$trailer) = @_;
		my $fh = $fcache->get($self->{fn}[1]);
		print $fh $$trailer;
		$$trailer = '';
	    }
	});
    } else {
	my $log = sub {
	    my ($self,$dr,$eof) = @_;
	    $$dr = '';
	    if ( $eof ) {
		my $req = $self->request_header;
		my $uri = $req->uri;
		if ( $uri !~m{^\w+://} ) {
		    my $host = $req->header('Host') || $self->{meta}{daddr};
		    $uri = "http://$host$uri";
		}
		my $resp = $self->response_header;
		printf("%d %05d.%04d %s %s -> %d ct:'%s', %s\n",
		    $self->{meta}{time},
		    $self->{flowid},
		    $self->{flowreqid},
		    $req->method, $uri,
		    $resp->code,
		    join(' ',$resp->header('content-type')),
		    join(' ', keys %{$self->{info}}),
		);
	    }
	    return '';
	};
	$self->add_hooks({
	    response_body => $log,
	    request_body  => sub { my ($self,$dr) = @_; $$dr = '' },
	});
    }

    return $self->SUPER::in_request_header($hdr,$time);
}

sub fatal {
    my ($self,$reason) = @_;
    trace( sprintf("%05d.%04d %s",$self->{flowid},$self->{flowreqid},$reason));
}



package myFileCache;
use fields qw(open closed max n);

sub new {
    my ($class,$max) = @_;
    my $self = fields::new($class);
    $self->{n} = 0;
    $self->{max} = $max||128;
    $self->{open} = {};
    $self->{closed} = {};
    return $self;
}

sub add {
    my ($self,$fname) = @_;
    return $self->get($fname,1);
}

sub del {
    my ($self,$fname) = @_;
    delete $self->{open}{$fname};
    delete $self->{closed}{$fname};
}

sub get {
    my ($self,$fname,$create) = @_;
    my $fh = $self->{open}{$fname};
    $fh = $fh && $fh->[0];
    if ( $create ) {
	_expire($self) if ! $fh;
	$fh = _open($self,'>',$fname) or return;
    }

    if ( ! $fh ) {
	$self->{closed}{$fname} or die "$fname not in pool";
	$fh = _open($self,'>>',$fname) or return;
	delete $self->{closed}{$fname};
    }

    $self->{open}{$fname} = [ $fh,$self->{n}++ ];
    return $fh;
}

sub _open {
    my ($self,$what,$fname) = @_;
    my $fh;
    while ( ! open( $fh,$what,$fname )) {
	if ( $!{ENFILE} || $!{EMFILE} || $!{ENOMEM} ) {
	    $self->{max}-- >1 or die "pool to small";
	    _expire($self);
	} else {
	    return;
	}
    }
    return $fh;
}

sub _expire {
    my ($self) = @_;
    my @fn = keys %{$self->{open}};
    @fn > $self->{max} or return;
    @fn = sort { $self->{open}{$a}[1] <=> $self->{open}{$b}[1] } @fn;
    while (@fn > $self->{max}) {
	my $fn = shift(@fn);
	delete $self->{open}{$fn};
	$self->{closed}{$fn} = 1;
    }
}
