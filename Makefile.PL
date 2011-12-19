use ExtUtils::MakeMaker;
require 5.10.0;
WriteMakefile(
	NAME => 'Net::Inspect',
	VERSION_FROM => 'lib/Net/Inspect.pm',
	PREREQ_PM => {
		'Net::Pcap' => 0,
	},
);
