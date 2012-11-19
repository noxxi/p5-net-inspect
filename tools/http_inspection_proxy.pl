#!/usr/bin/perl

=pod

TODO:
- decide after IMP processsing header, if detailed analysis with
  unchunking and umcompressing etc is really necessary
- work transparently, e.g. with iptables REDIRECT rules, instead of
  parsing Host header
- work as socks4 proxy, maybe as socks5 proxy too
=cut

# use private include path based on script path and name
BEGIN { 
    my $bin = __FILE__;
    $bin = readlink($bin) while ( -l $bin );
    unshift @INC, $bin =~m{^(.*?)(?:\.\w+)?$}; 
}

use strict;
use warnings;
use Getopt::Long qw(:config posix_default bundling);
use Net::Inspect::Debug qw($DEBUG debug %TRACE);
use IO::Socket::INET6;
use AnyEvent;

# local packages
use privRelay;
use privHTTPConn;
use privHTTPRequest;
use privDNS;
# use privIMP - on demand if IMP filters are used

sub usage {
    print STDERR <<USAGE;

Proxy to forward after inspecting/modifying request and response.
Removes unchunking and compression.

$0 Options* [ip:port]+
Options:
  -h|--help        show usage
  -d|--debug       debug mode
  -T|--trace T     enable traces
  -P|--pcapdir D   save connections as pcap files into D
  -F|--filter F    add named IMP plugin as filter, can be used multiple times
                   with --filter mod=args arguments can be given to the filter

Examples:
start proxy at 127.0.0.1:8888 and log all requests to /tmp as pcap files
 $0 --filter Net::IMP::SessionLog=dir=/tmp/&format=pcap  127.0.0.1:8888
start proxy at 127.0.0.1:8888 and log all form fields
 $0 --filter IMP_LogFormData 127.0.0.1:8888

USAGE
    exit(2);
}

my (@filter,$pcapdir);
GetOptions(
    'd|debug' => \$DEBUG,
    'T|trace=s' => sub { $TRACE{$_} = 1 for split(m/,/,$_[1]) },
    'h|help' => sub { usage() },
    'P|pcapdir=s' => \$pcapdir,
    'F|filter=s' => \@filter,
);
my @addr = @ARGV or usage("no listener");

if ($pcapdir) {
    die "pcap directory not writeable " unless -d $pcapdir && -w _;
    eval { require Net::PcapWriter } or 
	die "cannot load Net::PcapWriter, which is needed with --pcapdir option";
}

my $filter;
if (@filter) {
    eval { require privIMP } or 
	die "cannot load Net::IMP, which is needed for --filter option: $@";
    $filter = privIMP->new_factory(@filter)
}

# create connection fabric, attach request handling
my $req  = privHTTPRequest->new;
my $conn = privHTTPConn->new($req, pcapdir => $pcapdir, imp_factory => $filter );

# add hooks for unchunking and decompression
$req->add_hooks('unchunk','uncompress_te','uncompress_ce');


# create listeners
my @listen;
for my $addr (@addr) {
    my $srv = IO::Socket::INET6->new(
	LocalAddr => $addr,
	Listen    => 10,
	Reuse     => 1,
    ) or die "cannot listen to $addr: $!";
    push @listen, AnyEvent->io(
	fh => $srv,
	poll => 'r',
	cb => sub {
	    my $cl = $srv->accept or return;
	    privRelay->new($cl,$conn);
	}
    );
}

# on SIGUSR1 dump state of all relays
my $sw = AnyEvent->signal( signal => 'USR1', cb => sub {
    debug("-------- active relays ------------------");
    my @relays = privRelay->relays;
    debug(" * NO RELAYS") if ! @relays;
    $_->dump_state for(@relays);
    debug("-----------------------------------------");
});


# Mainloop
my $loopvar = AnyEvent->condvar;
$loopvar->recv;
exit;
