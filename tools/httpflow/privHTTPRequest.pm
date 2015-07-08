
# ----------------------------------------------------------------------------
# request object derived from HTTP::Request::InspectChain
# handles saving of request data into files or writing of request
# information to stdout
# ----------------------------------------------------------------------------

use strict;
use warnings;

package privHTTPRequest;
use base 'Net::Inspect::L7::HTTP::Request::InspectChain';
use fields qw(writer outdir fcache infosub flowid flowreqid fn chunked stat);
use Net::Inspect::Debug;

sub new {
    my ($class,%args) = @_;
    my $self = $class->SUPER::new;
    $self->{infosub} = $args{info}   || ref($class) && $class->{infosub};
    $self->{writer}  = $args{writer} || ref($class) && $class->{writer};
    $self->{outdir}  = $args{dir}    || ref($class) && $class->{outdir};
    $self->{fcache}  = $args{fcache} || ref($class) && $class->{fcache};
    die "no fcache given" if $self->{outdir} and ! $self->{fcache};
    return $self;
}
sub new_request {
    my ($self,$meta,$conn) = @_;
    my $obj = $self->SUPER::new_request($meta,$conn);
    $obj->{flowid} = $conn->{connid};
    $obj->{flowreqid}  = $meta->{reqid},
    $obj->{fn} = [];
    $obj->{stat} = {};
    return $obj;
}

sub DESTROY {
    my $self = shift;
    my $fn = $self->{fn} or return;
    $self->{fcache} && $self->{fcache}->del($_) for (@$fn);
}

sub in_request_header {
    my ($self,$hdr,$time) = @_;
    $self->{stat}{rqhdr} += length($hdr);

    my $write;
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
	    $self->{fcache}->add($fname) or die "cannot create $fname: $!";
	}
	$write = sub {
	    my ($self,$dir,$data) = @_;
	    my $fh = $self->{fcache}->get($self->{fn}[$dir]);
	    print $fh $data;
	}
    } elsif ( $self->{writer}) {
	my $obj = $self->{writer}->new_connection($self->{meta});
	$write = sub {
	    my ($self,$dir,$data) = @_;
	    $obj->{writer}->write($dir,$data);
	}
    }

    if ($write) {
	my $wfh = sub {
	    my ($self,$dir,$hdr) = @_;
	    $write->($self,$dir,$hdr);
	    return 0;
	};
	my $wfb = sub {
	    my ($self,$dir,$dr) = @_;
	    $write->($self,$dir,$$dr);
	    my $rv = $$dr;
	    $$dr = '';
	    return $rv;
	};

	$self->add_hooks({
	    request_header  => sub { $wfh->($_[0],0,${$_[1]}) },
	    response_header => sub { $wfh->($_[0],1,${$_[1]}) },
	    request_body    => sub { $wfb->($_[0],0,$_[1]) },
	    response_body   => sub { $wfb->($_[0],1,$_[1]) },
	    chunk_header    => sub { $wfh->($_[0],$_[1],${$_[2]}) },
	    chunk_trailer   => sub { $wfh->($_[0],$_[1],${$_[2]}) },
	});
    }

    return $self->SUPER::in_request_header($hdr,$time);
}

sub in_request_body {
    my ($self,$data,$eof,$time) = @_;
    $self->{stat}{rqbody} += length($data);
    return $self->SUPER::in_request_body($data,$eof,$time);
}

sub in_response_header {
    my ($self,$hdr,$time) = @_;
    $self->{stat}{rphdr} += length($hdr);
    return $self->SUPER::in_response_header($hdr,$time);
}

sub in_response_body {
    my ($self,$data,$eof,$time) = @_;
    $self->{stat}{rpbody} += length($data);
    my $rv = $self->SUPER::in_response_body($data,$eof,$time);
    if ($eof) {
	$self->{stat}{duration} = $time - $self->{meta}{time};
	$self->_info;
    }
    return $rv;
}

sub in_chunk_header {
    my ($self,$data,$time) = @_;
    $self->{stat}{rpbody} += length($data);
    $self->{stat}{chunks} ++;
    return $self->SUPER::in_chunk_header($data,$time);
}

sub in_chunk_trailer {
    my ($self,$data,$time) = @_;
    $self->{stat}{rpbody} += length($data);
    return $self->SUPER::in_chunk_trailer($data,$time);
}

sub in_data {
    my ($self,$dir,$data,$eof,$time) = @_;
    $self->{stat}{ $dir ? 'rpbody':'rqbody' } += length($data);
    my $rv = $self->SUPER::in_data($dir,$data,$eof,$time);
    if ($eof>1) {
	# both sides closed
	$self->{stat}{duration} = $time - $self->{meta}{time};
	$self->_info;
    }
    return $rv;
}

sub _info {
    my $self = shift;
    my $infosub = $self->{infosub} or return;

    # end of data
    my $req = $self->request_header;
    my $uri = $req->uri;
    if ( $uri !~m{^\w+://} ) {
	my $host = $req->header('Host') || $self->{meta}{daddr};
	$uri = "http://$host$uri";
    }
    my $resp = $self->response_header;
    $infosub->( 
	sprintf("%7.2f %05d.%04d %s %s -> %d ct:'%s', %s",
	    $self->{meta}{time},
	    $self->{flowid},
	    $self->{flowreqid},
	    $req->method, $uri,
	    $resp->code,
	    join(' ',$resp->header('content-type')),
	    join(' ', keys %{$self->{info}}),
	),
	{
	    meta   => $self->{meta},
	    flowid => $self->{flowid},
	    reqid  => $self->{flowreqid},
	    method => $req->method,
	    uri    => $uri,
	    req    => $req,
	    resp   => $resp,
	    info   => $self->{info},
	    stat   => $self->{stat},
	}
    );
}


sub fatal {
    my ($self,$reason) = @_;
    trace( sprintf("%05d.%04d %s",$self->{flowid},$self->{flowreqid},$reason));
}


1;
