use strict;
use warnings;

package privIMP;

use Net::Inspect::Debug qw(:DEFAULT $DEBUG);
use Net::IMP::Debug var => \$DEBUG, sub => \&debug;
use Net::IMP;
use fields (
    'factory',   # factory from new_factory
    'analyzer',  # analyzer from new_analyzer
    'request',   # privHTTPrequest object (weak ref)
    # original length of request header
    # plugin should keep this boundary, e.g. either replace or (pre)pass header
    # but not replace header with header+body or only part of header
    'rqhdr_len',
    'rqhdr_buf', # needed to buffer request header if handled in chunks
    'rqhdr_chg', # set if the header got changed
    # per dir data, e.g. buf[0],pos[1]...
    'buf',       # buffered data per dir
    'pos',       # base position of buf relative to input stream
    'canpass',   # can pass up to this position (for pass in future)
    'prepass',   # canpass is for IMP_PREPASS, not IMP_PASS
    'passed',    # offset up to which date were passed w/o inspecting them
);

use Scalar::Util 'weaken';

# create a new factory object
sub new_factory {
    my ($class,@mod) = @_;
    my @factory;
    for my $module (@mod) {
	# --filter mod=args
	my ($mod,$args) = $module =~m{^([a-z][\w:]*)(?:=(.*))?$}i
	    or die "invalid module $module";
	eval "require $mod" or die "cannot load $mod args=$args: $@";
	my %args = $mod->str2cfg($args//'');
	my $factory = $mod->new_factory(
	    rtypes => [
		IMP_PASS,
		IMP_PREPASS,
		IMP_REPLACE,
		IMP_TOSENDER,
		IMP_DENY,
		IMP_LOG,
		IMP_ACCTFIELD,
	    ],
	    %args
	) or croak("cannot create Net::IMP factory for $mod");
	push @factory,$factory;
    }

    @factory or return;
    if (@factory>1) {
	# for cascading filters we need Net::IMP::Cascade
	require Net::IMP::Cascade;
	my $cascade = Net::IMP::Cascade->new_factory( parts => [ @factory ]) 
	    or croak("cannot create Net::IMP::Cascade factory");
	@factory = $cascade;
    }

    my $self = fields::new($class);
    $self->{factory} = $factory[0];
    return $self;
}

# create a new analyzer based on the factory
sub new_analyzer {
    my ($factory,$request,$meta) = @_;

    # IMP plugins use different schema in meta than Net::Inspect
    my %meta = %$meta;
    $meta{$_->[1]} = delete $meta{$_->[0]} for(
	[ saddr => 'caddr' ], [ sport => 'cport' ], # [s]rc -> [c]lient
	[ daddr => 'saddr' ], [ dport => 'sport' ], # [d]st -> [s]erver
    );
    my $anl = $factory->{factory}->new_analyzer( meta => \%meta );

    my $self = fields::new(ref($factory));
    %$self = (
	request   => $request,
	analyzer  => $anl,
	buf       => ['',''],
	pos       => [0,0],
	canpass   => [0,0],
	prepass   => [0,0],
	passed    => [undef,undef],
	rqhdr_len => 0,
	rqhdr_buf => '',
	rqhdr_chg => '',
    );
    weaken($self->{request});
    weaken( my $wself = $self );
    $anl->set_callback( \&_imp_callback,$wself );

    return $self;
}

# process data
# if we had IMP_PASS or IMP_PREPASS with an offset into the future we might
# forward received data instead or parallel to sending them to the inspection
sub data {
    my ($self,$dir,$data) = @_;
    my $anl = $self->{analyzer} or die;
    return $anl->data($dir,undef) if ! defined $data; # eof

    # first call on dir == 0 will be complete request header, e.g.
    # called from in_request_header
    $self->{rqhdr_len} ||= length($data) if $dir == 0;

    my $canpass = $self->{canpass}[$dir];
    my ($fwd,$inspect);
    if ( $canpass == IMP_MAXOFFSET ) {
	# forward everything directly
	$fwd = $data;
    } elsif ( ! $canpass ) {
	# send everything to analyzer
	$self->{buf}[$dir] .= $data;
	$inspect = $data;
    } else {
	# we might forward some part of the incoming data directly
	my $rpass = $canpass - $self->{pos}[$dir];

	# some sanity checks if we did correct house keeping
	die "canpass <= buf.pos" if $rpass <= 0;
	die "expected buf[$dir] to be empty because of canpass" 
	    if $self->{buf}[$dir] ne '';

	if ( $rpass > length($data) ) {
	    # forward everything, canpass still points into future
	    $fwd = $data;
	} else {
	    # forward part or all, reset canpass because it was reached
	    $fwd = substr($data,0,$rpass,'');
	    $inspect = $self->{buf}[$dir] = $data;
	    $self->{canpass}[$dir] = 0;
	}
    }

    if ( defined $fwd ) {
	$self->{pos}[$dir] += length($fwd); # update pos

	if ($dir == 0 and $self->{rqhdr_len}>0 ) {
	    _handle_rqhdr($self,\$fwd,$self->{pos}[$dir],0);
	    die "should replace only request " if defined $fwd
	} 
    }

    if ( defined $fwd ) {
	$self->{request}->imp_forward($dir,$dir?0:1,$fwd);
	if ( $self->{prepass}[$dir] ) {
	    $inspect = defined($inspect) ? "$fwd$inspect":$fwd;
	} else {
	    # set passed to pos
	    $self->{passed}[$dir] = $self->{pos}[$dir];
	}
    }
    if ( defined $inspect ) {
	# add offset for previously passed data if necessary
	my $passed = $self->{passed}[$dir];
	$self->{passed}[$dir] = undef if $passed;
	$self->{analyzer}->data($dir,$inspect, $passed ? ($passed):());
    }
}

sub _imp_callback {
    my ($self,@rv) = @_;
    my $req = $self->{request};

    for my $rv (@rv) {
	my $typ = shift(@$rv);
	my ($fwd,$changed);
	if ( $typ == IMP_ACCTFIELD ) {
	    my ($k,$v) = @$rv;
	    $req->imp_acct($k,$v);
	    $req->xdebug("acct $k=$v");
	} elsif ( $typ == IMP_DENY ) {
	    my ($dir,$msg) = @$rv;
	    if ( defined $msg ) {
		$req->xdebug("deny($dir): $msg");
		$req->fatal($msg);
	    } else {
		$req->xdebug("deny($dir)");
		$req->{conn}{relay}->close;
	    }
	} elsif ( $typ == IMP_LOG ) {
	    my ($dir,$offset,$len,$lvl,$msg) = @$rv;
	    $req->xdebug("log($lvl,$dir): $msg");

	} elsif ( $typ ~~ [ IMP_PASS, IMP_PREPASS ] ) {
	    my ($dir,$offset) = @$rv;
	    my $canpass = $self->{canpass}[$dir];
	    if ( $canpass == IMP_MAXOFFSET 
		or $offset != IMP_MAXOFFSET and $offset <= $canpass ) {
		$req->xdebug("$typ($dir,$offset) - offset<canpass($canpass)");
		# nothing can override an earlier pass
		# except we can upgrade a prepass to pass
		$self->{prepass}[$dir] = 0 if $typ == IMP_PASS;

	    } elsif ( $offset == IMP_MAXOFFSET or
		$offset > $self->{pos}[$dir] + length($self->{buf}[$dir]) ) {
		$req->xdebug("$typ($dir,Future($offset))");
		$self->{canpass}[$dir] = $offset;
		$self->{prepass}[$dir] = ($typ == IMP_PREPASS);
		if ( $self->{buf}[$dir] ne '' ) {
		    $self->{pos}[$dir] += length($self->{buf}[$dir]);
		    $fwd = [$dir,$self->{buf}[$dir],$self->{pos}[$dir]];
		    $self->{buf}[$dir] = '';
		}
	    } elsif ( $offset <= $self->{pos}[$dir] ) {
		# info about data we already passed
		$req->xdebug("$typ($dir,Obsolete($offset)) - ignoring");
	    } else {
		# offset pointing inside the current buffered data
		# part or all of these data can now be forwarded
		my $len = $offset - $self->{pos}[$dir];
		$req->xdebug("$typ($dir,Inbuf($offset)): fwd=$len");
		$self->{canpass}[$dir] = 0;
		$self->{pos}[$dir] += $len;
		$fwd = [$dir,substr($self->{buf}[$dir],0,$len,''),$self->{pos}[$dir]];
	    }

	} elsif ( $typ == IMP_REPLACE ) {
	    my ($dir,$offset,$newdata) = @$rv;

	    # remove the data from buf which should be replaced
	    # replacing future data is not supported, replacing already handled
	    # data obviously not too
	    die "cannot replace already handled data: $typ($dir) ".
		"offset($offset)<=pos($self->{pos}[$dir])"
		if $offset <= $self->{pos}[$dir];
	    my $keep = $self->{pos}[$dir] + length($self->{buf}[$dir]) - $offset;
	    die "cannot replace future data: $typ($dir) offset($offset) -> keep($keep)"
		if $keep < 0;

	    # remove data from buf
	    $req->xdebug("$typ($dir,Inbuf($offset)) keep=$keep replace=".length($newdata));
	    $self->{buf}[$dir] = $keep ? substr($self->{buf}[$dir],-$keep,$keep) : '';
	    $self->{pos}[$dir] = $offset;

	    # and forward new data instead
	    $changed = 1;
	    $fwd = [$dir,$newdata,$offset] if $newdata ne '';

	} elsif ( $typ == IMP_TOSENDER ) {
	    my ($dir,$data) = @$rv;
	    $req->xdebug("$typ($dir) data=".length($data));
	    $req->imp_forward($dir,$dir,$data); # from == to
	}

	if ($fwd) {
	    my ($dir,$buf,$offset) = @$fwd;
	    if ($dir == 0 and $self->{rqhdr_len}>0 ) {
		_handle_rqhdr($self,\$buf,$offset,$changed);
		die "should replace only request " if defined $buf
	    } 
	    $req->imp_forward($dir,$dir?0:1,$buf) if defined $buf;
	}
    }
}

sub _handle_rqhdr {
    my ($self,$rfwd,$offset,$changed) = @_;
    $self->{rqhdr_buf} .= $$rfwd;
    $self->{rqhdr_chg} ||= $changed;
    my $fwd_over = $offset - $self->{rqhdr_len};

    if ( $fwd_over < 0 ) {
	# still header data missing
	$$rfwd = undef; # nothing to forward
	return;
    }
    $self->{rqhdr_len} = -1; # got at least header
    $$rfwd = $fwd_over>0 
	? substr($self->{rqhdr_buf},-$fwd_over,$fwd_over,'')  # got header and more
	: undef;                                              # got header only

    $self->{request}->imp_rqhdr($self->{rqhdr_buf},$self->{rqhdr_chg});
}

1;

