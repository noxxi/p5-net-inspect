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
use Net::Inspect::L4::UDP;

############################################################################
# Options
############################################################################
my ($infile,$dev,$nopromisc,@trace,$outdir);
GetOptions(
    'r=s' => \$infile,
    'i=s' => \$dev,
    'p'   => \$nopromisc,
    'h|help' => sub { usage() },
    'd|debug' => \$DEBUG,
    'T|trace=s' => sub { push @trace,split(m/,/,$_[1]) },
    'D|dir=s' => \$outdir,
) or usage();
usage('only interface or file can be set') if $infile and $dev;
$infile ||= '/dev/stdin' if ! $dev;
my $pcapfilter = join(' ',@ARGV);
$TRACE{$_} = 1 for(@trace);
die "cannot write to $outdir: $!" if $outdir and ! -w $outdir || ! -d _;

sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<USAGE;

reads data from pcap file or device and extracts tcp and udp streams.

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
		     e.g. tcp, rawip
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

# parse hierarchy
############################################################################

my $tcp = Net::Inspect::L4::TCP->new( ConnWriter->new("$outdir/tcp-"));
my $udp = Net::Inspect::L4::UDP->new( ConnWriter->new("$outdir/udp-"));
my $raw = Net::Inspect::L3::IP->new([$tcp,$udp]);
my $pc  = Net::Inspect::L2::Pcap->new($pcap,$raw);


# Mainloop
############################################################################
my $time;
pcap_loop($pcap,-1,sub {
    my (undef,$hdr,$data) = @_;
    if ( ! $time || $hdr->{tv_sec}-$time>10 ) {
	$tcp->expire($time = $hdr->{tv_sec});
    }
    return $pc->pktin($data,$hdr);
},undef);


package ConnWriter;
use base 'Net::Inspect::Connection';
use fields qw(prefix flowid saddr sport daddr dport time);
use Net::Inspect::Debug;

my $flowid = 0;
sub new {
    my ($class,$dir) = @_;
    my $self = $class->SUPER::new;
    if ( ref $class ) {
	$self->{prefix} = $dir || $class->{prefix};
	$self->{flowid} = ++$flowid;
    } else {
	$self->{prefix} = $dir;
    }
    return $self;
}

sub syn { 1 }
sub new_connection {
    my ($self,$meta) = @_;
    my $obj = $self->new; # clones attached flows
    %$obj = ( %$obj, 
	saddr => $meta->{saddr},
	sport => $meta->{sport},
	daddr => $meta->{daddr},
	dport => $meta->{dport},
	time  => $meta->{time},
    );
    return $obj;
}

sub in {
    my ($self,$dir,$data,$eof,$time) = @_;
    my $fname = sprintf("%s%05d.%d-%s.%s-%s.%s-%d",
	$self->{prefix},
	$self->{flowid},
	$self->{time},
	$self->{saddr}, $self->{sport},
	$self->{daddr}, $self->{dport},
	$dir
    );
    open( my $fh,'>>',$fname ) or die "open $fname: $!";
    print $fh $data;
    return length($data);
}

# UDP
sub pktin {
    my $self = shift;
    if ( ref($_[1])) {
	# packet w/o connection
	my ($data,$meta) = @_;
	# create connection
	my $conn = $self->new_connection($meta);
	$conn->in(0,$data,0,$meta->{time});
	return $conn;
    } else {
	# already connection
	my ($dir,$data,$time) = @_;
	return $self->in($dir,$data,0,$time);
    }
}

