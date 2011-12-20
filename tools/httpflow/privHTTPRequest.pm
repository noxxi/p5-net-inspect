
# ----------------------------------------------------------------------------
# request object derived from HTTP::Request::InspectChain
# handles saving of request data into files or writing of request
# information to stdout
# ----------------------------------------------------------------------------

use strict;
use warnings;

package privHTTPRequest;
use base 'Net::Inspect::L7::HTTP::Request::InspectChain';
use fields qw(outdir fcache infosub flowid flowreqid fn chunked);
use Net::Inspect::Debug;

sub new {
    my ($class,%args) = @_;
    my $self = $class->SUPER::new;
    $self->{outdir}  = $args{dir}    || ref($class) && $class->{outdir};
    $self->{fcache}  = $args{fcache} || ref($class) && $class->{fcache};
    $self->{infosub} = $args{info}   || ref($class) && $class->{infosub};
    die "no fcache given" if $self->{outdir} and ! $self->{fcache};
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
    my $self = shift;
    my $fn = $self->{fn} or return;
    $self->{fcache} && $self->{fcache}->del($_) for (@$fn);
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
	    $self->{fcache}->add($fname) or die "cannot create $fname: $!";
	}
	my $wfh = sub {
	    my ($self,$dir,$hdr) = @_;
	    my $fh = $self->{fcache}->get($self->{fn}[$dir]);
	    print $fh $hdr;
	    return 0;
	};
	my $wfb = sub {
	    my ($self,$dir,$dr) = @_;
	    my $fh = $self->{fcache}->get($self->{fn}[$dir]);
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
		my $fh = $self->{fcache}->get($self->{fn}[1]);
		print $fh "\r\n" if $self->{chunked}++;
		print $fh $$hdr;
		$$hdr = '';
	    },
	    chunk_trailer   => sub {
		my ($self,$trailer) = @_;
		my $fh = $self->{fcache}->get($self->{fn}[1]);
		print $fh $$trailer;
		$$trailer = '';
	    }
	});
    } 
    if ( my $infosub = $self->{infosub} ) {
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
		$infosub->( 
		    sprintf("%d %05d.%04d %s %s -> %d ct:'%s', %s",
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
		    }
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


1;
