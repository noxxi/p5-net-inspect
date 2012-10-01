use ExtUtils::MakeMaker;
require 5.10.0;
WriteMakefile(
    NAME => 'Net::Inspect',
    VERSION_FROM => 'lib/Net/Inspect.pm',
    PREREQ_PM => {
	'Net::Pcap' => 0,
	'Scalar::Util' => 0,
	'HTTP::Request' => 0,
	'HTTP::Response' => 0,
    },
    LICENSE => 'perl',
);
