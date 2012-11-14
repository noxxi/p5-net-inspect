use strict;
use warnings;

package privRelay;
use fields (
    'fds',      # file descriptors
    'conn',     # privHRTTPConn object
);

use Net::Inspect::Debug;
use Scalar::Util 'weaken';
use AnyEvent;

# active relay, inserted in new, removed in $idlet timer
my @relays;
sub relays { return grep { $_ } @relays }

# creates new relay and puts it into @relays as weak reference
sub new {
    my ($class,$cfd,$conn) = @_;
    my $self = fields::new($class);
    debug("create relay $self");

    my $cobj = $conn->new_connection({
	daddr => $cfd->sockhost,
	dport => $cfd->sockport,
	saddr => $cfd->peerhost,
	sport => $cfd->peerport,
    },$self);

    #debug("create connection $cobj");
    $self->{conn} = $cobj;
    my $cfo = $self->{fds}[0] = privRelay::FD->new(0,$cfd,$self,1);
    $cfo->mask( r => 1 ); # enable read 

    push @relays, $self;
    weaken($relays[-1]);

    return $self;
}

sub DESTROY {
    my $self = shift;
    $self->xdebug("destroy relay $self");
}

sub account {
    my ($self,%args) = @_;
    if ( my $t = delete $args{start} ) {
	$args{duration} = AnyEvent->now - $t;
    }
    my $msg = join(' ', map { "$_=$args{$_}" } sort keys %args);
    print STDERR "ACCT $msg\n";
}

sub xdebug {
    my $self = shift;
    my $conn = $self->{conn};
    if ( my $xdebug = UNIVERSAL::can($conn,'xdebug') ) {
	unshift @_,$conn;
	goto &$xdebug;
    } else {
	debug(@_);
    }
}


sub fatal {
    my ($self,$reason) = @_;
    warn "[fatal] ".$self->{conn}->id." $reason\n";
    $self->close;
    return 0;
}

sub connect:method {
    my ($self,$to,$host,$port,$callback,$reconnect) = @_;
    my $fo = $self->{fds}[$to] ||= privRelay::FD->new($to,undef,$self);
    $fo->connect($host,$port,$callback,$reconnect);
}

# masks/unmasks fd for dir, rw = r|w
sub mask {
    my ($self,$dir,$rw,$v) = @_;
    my $fd = $self->{fds}[$dir] or do {
	warn "fd dir=$dir does not exists\n";
	return;
    };
    $fd->mask($rw,$v);
}

# send some data via fd dir
sub forward {
    my ($self,$from,$to,$data) = @_;
    my $fo = $self->{fds}[$to] or return
	$self->fatal("cannot write to $to - no such fo");
    $self->xdebug("$to>$from - forward %d bytes",length($data));
    $fo->write($data,$from);
}

# closes relay
sub close:method {
    my $self = shift;
    #debug("close $self");
    undef $self->{conn};
    @relays = grep { !$_ or $_ != $self } @relays;
    $_ && $_->close for @{$self->{fds}};
    @{$self->{fds}} = ();
}

# shutdown part of relay
sub shutdown:method {
    my ($self,$dir,$rw,$force) = @_;
    my $fo = $self->{fds}[$dir] or return;
    $fo->shutdown($rw,$force);
}

# check for condition, where we cannot transfer anymore data:
# - nowhere to read
# - nowhere to write too
sub closeIfDone {
    my $self = shift;
    my $sink = my $src = '';
    for my $fo (@{$self->{fds}}) {
	$fo && $fo->{fd} or next;
	$sink .= $fo->{dir} if $fo->{status} & 0b010; # not write-closed
	$src  .= $fo->{dir} if $fo->{status} & 0b100; # not read-closed
	return if $fo->{wbuf} ne ''; # still has data to write
    }

    if ( $sink eq ''       # nowhere to write
	or $src eq ''      # nowhere to read from new data
    ) {
	# close relay
	return $self->close;
    }

    return;
}


# dump state to debug
sub dump_state {
    my $self = shift;
    my $conn = $self->{conn};
    if ( my $fds = $self->{fds} ) {
        my @st;
        for( my $i=0;$i<@$fds;$i++) {
            push @st, sprintf("%d=%03b",$i,$fds->[$i]{status} || 0);
        }
        $conn->xdebug("status @st");
    }
    $conn->dump_state();
}


my $idlet = AnyEvent->timer( 
    after => 5, 
    interval => 5, cb => sub {
        @relays = grep { $_ } @relays or return;
        #debug("check timeouts for %d conn",+@relays);
        my $now = AnyEvent->now;
	RELAY: for my $r (@relays) {
	    for my $fo (@{$r->{fds}}) {
		next RELAY if $_->{didit} + 30 > $now;
	    }
	    $r->xdebug("close because of timeout");
            $r->close
        }
    }
);


package privRelay::FD;
use Carp 'croak';
use Scalar::Util 'weaken';
use Net::Inspect::Debug;
use privDNS;
use AnyEvent::Socket qw(tcp_connect format_address);

use fields (
    'dir',        # direction 0,1
    'fd',         # file descriptor
    'host',       # destination hostname
    'status',     # bitmap of read_shutdown|write_shutdown|connected
    'relay',      # weak link to relay
    'didit',      # time of last activity (read/write)
    'rbuf',       # read buffer (read but not processed)
    'rsub',       # read handler
    'rwatch',     # AnyEvent watcher - undef if read is disabled
    'wbuf',       # write buffer (not yet written to socket)
    'wsub',       # write handler
    'wwatch',     # AnyEvent watcher - undef if write is disabled
    'wsrc',       # source of writes for stalled handling
);

sub new {
    my ($class,$dir,$fd,$relay,$connected) = @_;
    my $self = fields::new($class);
    $self->{dir} = $dir;
    $self->{fd} = $fd;
    $self->{status} = $connected ? 0b001 : 0;
    #weaken( $self->{relay} = $relay );
    $self->{relay} = $relay;
    $self->{rbuf} = $self->{wbuf} = '';
    return $self;
}

sub xdebug {
    my $self = shift;
    my $conn = $self->{relay}{conn};
    if ( my $xdebug = UNIVERSAL::can($conn,'xdebug') ) {
	my $msg = "[$self->{dir}] ".shift(@_);
	unshift @_,$conn,$msg;
	goto &$xdebug;
    } else {
	debug(@_);
    }
}

sub close:method { 
    my $self = shift;
    $self->xdebug("close");
    if ( $self->{fd} ) {
	$self->{fd} = undef;
	delete $self->{relay}{fds}[$self->{dir}];
	$self->{relay}->closeIfDone;
    }
    %$self = ();
}

sub reset {
    my $self = shift;
    $self->xdebug("reset");
    close($self->{fd}) if $self->{fd};
    $self->{fd} = 
	$self->{rwatch} = $self->{rsub} = 
	$self->{wwatch} = $self->{wsub} = 
	$self->{host} =
	$self->{wsrc} =
	undef;
    $self->{status} = $self->{didit} = 0;
    $self->{rbuf} = $self->{wbuf} = '';
    return 1;
}

# attempt to shutdown fd.
# don't shutdown(1) if wbuf ne '' && ! $force
sub shutdown:method {
    my ($self,$rw,$force) = @_;
    my $what = $rw eq 'r' ? 0 : $rw eq 'w' ? 1 : $rw;
    my $stat = $what ? 0b010 : 0b100;
    return if $self->{status} & $stat && ! $force; # no change

    $self->xdebug("shutdown $rw fn=".fileno($self->{fd}));

    $self->{status} |= $stat;
    if ( $rw && $self->{wbuf} ne '' ) {
	return if ! $force; # will shutdown once all is written
	$self->{wbuf} = ''; # drop rest
	undef $self->{wsrc}; # don't re-enable, unclear state
	undef $self->{wwatch};
    }
	
    shutdown($self->{fd},$what);
    # shutdown on both sides -> close
    return $self->close if $self->{status} & 0b110 == 0b110;

    # if all fd are closed, close the relay too
    $self->{relay}->closeIfDone;

    return 1;
}


sub mask {
    my ($self,$rw,$mask) = @_;
    #debug("$self->{dir} $self->{fd} fn=".fileno($self->{fd})." $rw=>$mask");
    if ( $rw eq 'r' ) {
	if ( ! $mask ) {
	    # disable read
	    undef $self->{rwatch};
	} elsif ( ! $self->{rwatch} ) {
	    # enable read if not enabled
	    $self->{status} & 0b100 and return 0; # read shutdown already
	    $self->{rsub} ||= sub { _read($self) }; 
	    $self->{rwatch} = AnyEvent->io(
		fh => $self->{fd},
		poll => 'r',
		cb => $self->{rsub}
	    );
	}
    } elsif ( $rw eq 'w' ) {
	if ( ! $mask ) {
	    # disable write
	    undef $self->{wwatch};
	} elsif ( $self->{wbuf} ne '' and ! $self->{wwatch} ) {
	    $self->{status} & 0b010 and return 0; # write shutdown already
	    $self->{wsub} ||= sub { _writebuf($self) }; 
	    $self->{wwatch} = AnyEvent->io(
		fh => $self->{fd},
		poll => 'w',
		cb => $self->{wsub}
	    );
	}
    } else {
	croak("cannot set mask for $rw");
    }
    return 1;
}

# write data, gets written from relay->send
sub write:method {
    my ($self,$data,$from) = @_;
    my $n = 0;
    if ( $self->{wbuf} eq '' ) {
	# no buffered data, set as buffer and try to write immediately
	$self->{wbuf} = $data;
	$n = _writebuf($self,$from);
    } else {
	# only append to buffer, will be written on write ready
	$self->{wbuf} .= $data;
    }

    if ( $self->{wbuf} ne '' 
	&& ! $self->{wsrc}{$from}++ ) {
	# newly stalled, disable reads on $from for now
	$self->{relay}->mask($from,0);
    }
    return $n;
}

# gets called if wbuf is not empty, either from write or from callback
# when fd is writable again
sub _writebuf {
    my $self = shift;
    #debug("write $self fn=".fileno($self->{fd}));
    my $n = syswrite($self->{fd},$self->{wbuf});
    #debug("write done: ". (defined $n ? $n : $!));
    if ( ! defined $n ) {
        $self->{relay}->fatal("write($self->{dir}) failed: $!")
	    unless $!{EINTR} or $!{EAGAIN};
        return;
    }

    substr($self->{wbuf},0,$n,'');
    $self->{didit} = AnyEvent->now;

    if ( $self->{wbuf} eq '' ) {
        # wrote everything
        #debug("all written to $self->{dir}");
        undef $self->{wwatch};

	if ( $self->{status} & 0b100 ) {
	    # was marked for shutdown
	    shutdown($self->{fd},1);
	    # if all fd are closed, close the relay too
	    $self->{relay}->closeIfDone;
	}
        # enable read again on stalled fd
	if ( my $src = $self->{wsrc} ) {
	    $self->{relay}->mask($_,1) for (keys %$src);
	}
    }
    return $n;
}

# gets called if data are available on the socket
# but only, if we don't have unsent data in wbuf
# reads data into rbuf and calls connection->in
sub _read:method {
    my $self = shift;
    #debug("read $self fn=".fileno($self->{fd}));
    my $n = sysread($self->{fd},$self->{rbuf},2**15,length($self->{rbuf}));
    #debug("read done: ". (defined $n ? $n : $!));
    if ( ! defined $n ) {
	if ( ! $!{EINTR} and ! $!{EAGAIN} ) {
	    # complain only if we are inside a request
	    # timeouts after inactivity are normal
	    return $self->{relay}->fatal("read($self->{dir}) failed: $!")
		if $self->{relay}{conn}->open_requests;

	    # close connection
	    $self->xdebug("closing relay because of read error on $self->{dir}");
	    return $self->{relay}->close;
	}
        return;
    }

    $self->{didit} = AnyEvent->now;
    my $bytes = $self->{relay}{conn}
	->in($self->{dir},$self->{rbuf},!$n,$self->{didit});

    # fd/relay closed from within in() ?
    defined $self->{fd} or return; 

    if ( $bytes ) {
	# connection accepted $bytes
	substr($self->{rbuf},0,$bytes,'');
    }

    return $self->{relay}->fatal(
	"connection should have taken all remaining bytes on eof")
	if !$n && $self->{rbuf} ne '';

    $self->shutdown('r') if ! $n;
}

sub connect:method {
    my ($self,$host,$port,$callback,$reconnect) = @_;

    # down existing connection if we should connect to another host
    $self->reset if $self->{fd} and 
	( $reconnect or $self->{host}||'' ne "$host.$port" );

    # if we have a connection already, keep it
    if ( $self->{status} & 0b001 ) { # already connected 
	$callback->();
	return 1;
    }

    # (re)connect
    $self->xdebug("connecting to $host.$port");
    # async dns lookup + connect
    privDNS::lookup($host, sub {
	$self->{relay} or return; # relay already closed
	if ( my $addr = shift ) {
	    tcp_connect($addr,$port, sub {
		if ( my $fd = shift ) {
		    $self->{relay} or return; # relay already closed
		    $self->{fd} = $fd;
		    $self->{status} = 0b001;
		    $self->{host} = "$host.$port";
		    $self->xdebug("connect done");
		    $self->mask( r => 1 );
		    $callback->();
		} else {
		    privDNS::uncache($host,$addr);
		    $self->{relay}->fatal("connect to $host.$port failed: $!");
		}
	    });
	} else {
	    $self->{relay}->fatal(
		"connect to $host.$port failed: no such host (DNS)");
	}
    });
    return -1;
}

1;
