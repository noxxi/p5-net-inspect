# sample IMP plugin to log formulare data
# e.q query_string and POST data

use strict;
use warnings;
package IMP_LogFormData;
use base 'Net::IMP::Base';
use fields (
    'rqbuf',  # buffered data from request
    'req',    # HTTP::Request object for request header
    'info',   # collection of infos for logging after request end
    'btype',  # content type from request body, eg. 
              # application/x-www-form-urlencoded or multipart/form-data
);

use Net::IMP qw(:DEFAULT :log); # constants
require HTTP::Request;
use Net::IMP::Debug;

sub USED_RTYPES {
    # we don't change anything but need to analyze, so we can PREPASS
    # everything initially until Inf and later upgrade it to PASS
    # because we are only interested in request header and body, data 
    # from server can be passed from the beginning
    return ( 
	IMP_PREPASS,
	IMP_PASS,
	IMP_DENY,    # on parsing errors
	IMP_LOG,     # somewhere to log the info about form data
    );
}

sub new_analyzer {
    my ($class,%args) = @_;
    my $self = $class->SUPER::new_analyzer(%args);
    $self->run_callback(
	# prepass all from request
	[ IMP_PREPASS,0,IMP_MAXOFFSET ],
	# we don't even need to look at response
	[ IMP_PASS,1,IMP_MAXOFFSET ],
    );
    $self->{rqbuf} = '';
    return $self;
}

sub data {
    my ($self,$dir,$data) = @_;
    return if $dir == 1; # response - we should not get these except for eof
    $self->{rqbuf} .= $data;
    if ( ! $self->{req} ) {
	if ( $self->{rqbuf} =~m{(\r?)\n\1\n}g ) {
	    #debug("got request");
	    # end of header
	    my $req = substr($self->{rqbuf},0,pos($self->{rqbuf}),'');
	    $req = $self->{req} = HTTP::Request->parse($req) or do {
		# failed to parse
		$self->run_callback(
		    [ IMP_DENY,0,"failed to parse request header" ]);
		return;
	    };
	    if ( my @qp = $req->uri->query_form ) {
		#debug("got query_string @qp");
		my @param;
		for(my $i=0;$i<@qp;$i+=2 ) {
		    push @param,[ $qp[$i], $qp[$i+1] ];
		}
		$self->{info}{'header.query_string'} = \@param
	    }
	    my $ct = $req->content_type;
	    if ( $ct && $req->method eq 'POST' and 
		$ct ~~ ['application/x-www-form-urlencoded','multipart/form-data']
		){
		#debug("got content-type $ct");
		$self->{btype} = $ct;
	    } else {
		# no need to analyze further
		#debug("no or no interesting body");
		$self->_log_formdata() if $self->{info};
		$self->{rqbuf} = ''; # throw away
		$self->run_callback( [ IMP_PASS,0,IMP_MAXOFFSET ]);
		return;
	    }
	} else {
	    # eof in request header or need more data
	    return;
	}
    }

    if ( $data//'' eq '' ) {
	# eof
	# parse body if necessary
	#debug("eof on $dir");
	if ( ! $self->{btype} ) {
	} elsif ( $self->{btype} eq 'application/x-www-form-urlencoded' ) {
	    my @param;
	    for( split( '&',$self->{rqbuf}) ) {
		my ($k,$v) = split('=',$_,2);
		for($k,$v) {
		    s{\+}{ }g;
		    s{%([\da-fA-F]{2})}{ chr(hex($1)) }esg;
		}
		push @param,[$k,$v];
	    }
	    $self->{info}{'body.urlencoded'} = \@param;
	    
	} elsif ( $self->{btype} eq 'multipart/form-data' ) {
	    my (undef,$boundary) = $self->{req}->header('content-type') 
		=~m{;\s*boundary=(\"?)([^";,]+)\1}i;
	    if ( ! $boundary ) {
		$self->run_callback([
		    IMP_DENY,0,
		    "missing boundary for multipart/form-data"
		]);
	    }
	    # we might use MIME:: heere, but this would be yet another non-CORE
	    # dependency :(
	    # this is quick and dirty and we just skip param on errors, but 
	    # this is just a demo!
	    my @param;
	    for my $part ( split( 
		m{^--\Q$boundary\E(?:--)?\r?\n}m, 
		$self->{rqbuf} )) {
		$part =~m{\A(.*?(\r?\n))\2(.*)}s or next;
		my ($hdr,$v) = ($1,$3);
		my ($cd) = $hdr =~m{^Content-Disposition:[ \t]*(.*(?:\r?\n[ \t].*)*)}mi
		    or do {
		    debug("no content-disposition in multipart header: $hdr");
		    next;
		};
		$cd =~s{\r?\n}{}g;
		my $name = $cd =~m{;\s*name=(?:\"([^\"]+)\"|([^\s\";]+))} && ($1||$2);
		$name or do {
		    debug("no name in content-disposition in multipart header: $hdr");
		    next;
		};
		my $fname = $cd =~m{;\s*filename=(?:\"([^\"]+)\"|([^\s\";]+))} && ($1||$2);
		$v =~s{\r?\n\Z}{};
		$v = "UPLOAD:$fname (".length($v)." bytes)" if $fname; # don't display content of file
		push @param, [$name,$v];
	    }
	    $self->{info}{'body.multipart'} = \@param;
	} else {
	    # should not happen, we set btype only if we can handle the type
	    die "unhandled POST content-type $self->{btype}"
	}
	$self->_log_formdata();

    } elsif ( $self->{btype} ) {
	# add to buf to analyze later
	$self->{rqbuf} .= $data;
    }
}


sub _log_formdata {
    my $self = shift;
    my $info = $self->{info} or return;
    # report form information if any, preferable as YAML, but fall back to
    # Data::Dumper, which is in core
    my $text;
    if ( eval { require YAML } ) {
	$text = YAML::Dump($info)
    } elsif ( eval { require YAML::Tiny } ) {
	$text = YAML::Tiny::Dump($info)
    } elsif ( eval { require Data::Dumper }) {
	$text = Data::Dumper->new([$info])->Terse(1)->Dump;
    } else {
	# Data::Dumper is perl core!
	die "WTF, not even Data::Dumper is installed?";
    }
    $self->run_callback([ IMP_LOG,0,0,0,IMP_LOG_INFO,$text ]);
}

