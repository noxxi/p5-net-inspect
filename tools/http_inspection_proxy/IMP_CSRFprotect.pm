# CSRF protection based on idea of 
# Automatic and Precise Client-Side Protection against CSRF Attacks
# https://lirias.kuleuven.be/bitstream/123456789/311551/1/paper.pdf
#
# remove Cookies and Authorization info from request to domain T, if
# - Referer/Origin is missing or points to different domain O 
# - and there is no trusted relationship between domains O and T 
# Trusted relationship means, if either
# - T and O share the same top level domain, which is not a global TLD
# - or there was an earlier request to T, which redirected to O
# - or there was an earlier form submit (e.g. POST or GET with query_string)
#   to O, originating from T (e.g. T as Referer/Origin)

use strict;
use warnings;
package IMP_CSRFprotect;
use base 'Net::IMP::Base';
use fields (
    'rqhdr_done',   # request header
    'rphdr_done',   # response header
    'target',       # target domain from request header
    'origin',       # domain from origin/referer request header
);

use Net::IMP qw(:DEFAULT :log);
use Net::IMP::Debug;

# FIXME - should be database backed and maybe shared between processes
# and should be expire after a while, unless refreshed
my %CD_TRUST;   # {target}{origin} - eg. request to target trusted from origin
my %CD_UNTRUST; # {target}{origin} - yet untrusted cross domain relation

sub USED_RTYPES { return (
    IMP_REPLACE, # remove Cookie/Authorization header
    IMP_LOG,     # log if we removed something
    IMP_DENY,    # bad requests/responses
    IMP_PASS,
)}

sub new_analyzer {
    my ($class,%args) = @_;
    my $self = $class->SUPER::new_analyzer(%args);
    $self->run_callback(
	# we will not modify response, but need to look at the response
	# header to detect redirects. After the response header was seen
	# this will be upgraded to IMP_PASS
	[ IMP_PREPASS,1,IMP_MAXOFFSET]
    );
    return $self;
}

sub data {
    my ($self,$dir,$data) = @_;
    my @rv;
    if ( $dir == 0 ) {
	return if $self->{rqhdr_done};

	# request header
	# modify if necessary, rest of request can be forwarded w/o inspection
	my $len = length($data);
	if ( defined( my $newdata = _modify_rqhdr($self,$data))) {
	    push @rv, [ IMP_REPLACE,0,$len,$newdata ];
	}
	push @rv, [ IMP_PASS,0,IMP_MAXOFFSET ];
	$self->{rqhdr_done} = 1;
    } else {
	return if $self->{rphdr_done};

	# response header
	_analyze_rphdr($self,$data);
	push @rv, [ IMP_PASS,1,IMP_MAXOFFSET ]; # upgrade to IMP_PASS
	$self->{rphdr_done} = 1;
    }

    $self->run_callback(@rv);
}

# extract target and origin domain
# if they differ remove cookies and authorization infos unless we have
#   an established trust between these domains
my $rx_host = qr{([\w\-.]+|\[[\da-fA-F:.]+\])};
my $rx_host_from_url = qr{^https?://$rx_host};
sub _modify_rqhdr {
    my ($self,$hdr) = @_;
    
    # determine target
    my (@target) = $hdr =~m{\A\w+[ \t]+http://$rx_host};
    @target = _gethdr($hdr,'Host',$rx_host) if ! @target;
    if ( ! @target or @target>1 ) {
	$self->run_callback(
	    [ IMP_LOG,0,0,0,IMP_LOG_WARNING,
		"cannot determine target from request\n".$hdr ],
	    [ IMP_DENY,0, "cannot determine target from request" ]
	);
	return;
    }

    # determine referer/origin domain
    my @origin = _gethdr($hdr,'Origin',$rx_host_from_url);
    @origin = _gethdr($hdr,'Referer',$rx_host_from_url) if ! @origin;
    if ( @origin > 1 ) {
	# invalid: conflicting origins
	$self->run_callback(
	    [ IMP_LOG,0,0,0,IMP_LOG_WARNING,
		"conflicting origins in request\n".$hdr ],
	    [ IMP_DENY,0, "conflicting origins in request" ]
	);
	return;
    }

    if ( ! @origin ) {
	# we have no origin to check trust inside request
	debug("no origin to check trust in request to @target");

    } else {
	# do nothing unless the request is cross-origin
	$self->{origin} = $origin[0];
	$self->{target} = $target[0];
	return if $origin[0] eq $target[0];

	# implicite trust when both have the same root-domain
	my $origin = _rootdom($origin[0]);
	my $target = _rootdom($target[0]);
	if ( $origin eq $target ) {
	    debug("trusted request from $origin[0] to $target[0] (same root-dom)");
	    return 
	}

	# check established trust through previous cross-domain handshake
	if ( $CD_TRUST{$target}{$origin} || $CD_TRUST{$origin}{$target} ) {
	    debug("trusted request from $origin to $target");
	    $CD_TRUST{$target}{$origin} = 1; # refresh
	    return 
	} elsif ( delete $CD_UNTRUST{$origin}{$target} ) {
	    # we had a request in the opposite direction
	    # trust established
	    debug("trust established between $origin and $target");
	    $CD_TRUST{$target}{$origin} = 1;
	    return;
	}

	# no trust (yet) 
	if ( $hdr =~m{\A(POST |GET .*\?\S)} ) {
	    # formular data: either POST request or GET with query_string
	    # store relation hoping that it gets verified from the other side
	    debug("(yet) untrusted formular request from $origin to $target");
	    $CD_UNTRUST{$target}{$origin} = 1;
	} else {
	    # just normal cross-domain requests
	    debug("untrusted non-formular request from $origin to $target");
	}
    }

    # remove cookies and authorization info, because there is no 
    # trusted cross-domain relation
    my $rv = undef;
    my @del;
    push @del,$1 while ( $hdr =~s{^(Cookie|Cookie2|Authorization):[ \t]*(.*(?:\n[ \t].*)*)\n}{}im );
    if (@del) {
	$rv = $hdr;
	$self->run_callback([ 
	    IMP_LOG,0,0,0,IMP_LOG_INFO,
	    "removed cross-origin session credentials (@del) for request @origin -> @target" 
	]);
    }
    return $rv;
}

# find out if response header contains redirect
sub _analyze_rphdr {
    my ($self,$hdr) = @_;
    # we are only interested in temporal redirects
    $hdr =~m{\AHTTP/1\.[01] 30[237]} or return; 

    my @location = _gethdr($hdr,'Location',$rx_host_from_url)
	or return; # no redirect
    if ( @location > 1 ) {
	# invalid: multiple conflicting redirects
	$self->run_callback(
	    [ IMP_LOG,0,0,0,IMP_LOG_WARNING,
		"conflicting redirects in response\n".$hdr ],
	    [ IMP_DENY,0, "conflicting redirects in response" ]
	);
	return;
    }
    my $location = $location[0];
    my $target   = $self->{target} or return;
    return if $target eq $location; # implicit trust

    $target   = _rootdom($target);
    $location = _rootdom($location);
    return if $target eq $location; # implicit trust same rootdom



    if ( $CD_TRUST{$target}{$location} ) {
	debug("refresh trust between $location and $target");
	$CD_TRUST{$target}{$location} = 1;
    } elsif ( delete $CD_UNTRUST{$target}{$location} ) {
	debug("added trust between L=$location and T=$target due to request(to T,origin L) and redirect(from T,to L)");
	$CD_TRUST{$target}{$location} = 1;
    }
}

sub _gethdr {
    my ($hdr,$key,$rx) = @_;
    my @val;
    for ( $hdr =~m{^\Q$key\E:[ \t]*(.*(?:\n[ \t].*)*)}mgi ) {
	s{\r\n}{}g; 
	s{\s+$}{}; 
	s{^\s+}{};
	push @val, m{$rx};
    }
    my %v;
    return grep { ! $v{$_}++ } @val;
}

BEGIN {
    if ( eval { require WWW::CSP::PublicDNSSuffix } ) {
	*_rootdom = sub {
	    my ($rest,$tld) = WWW::CSP::PublicDNSSuffix::public_suffix( shift );
	    return $rest =~m{([^.]+)$} ? "$1.$tld" : undef;
	}
    } elsif ( eval { require Mozilla::PublicSuffix }) {
	*_rootdom = sub {
	    my $host = shift;
	    my $suffix = Mozilla::PublicSuffix::public_suffix($host);
	    return $host =~m{([^\.]+\.\Q$suffix)} ? $1:undef,
	}
    } elsif ( my $suffix = eval { 
	require Domain::PublicSuffix; 
	Domain::PublicSuffix->new 
    }) {
	*_rootdom = sub { return $suffix->get_root_domain( shift ) }
    } else {
	die "need one of Domain::PublicSuffix, Mozilla::PublicSuffix or WWW::CSP::PublicDNSSuffix"
    }
}

1;
