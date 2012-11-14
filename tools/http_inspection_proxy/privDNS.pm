############################################################################
# DNS cache
############################################################################

use strict;
use warnings;
package privDNS;
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

1;
