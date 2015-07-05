#!/usr/bin/perl -w
# $Revision$
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# * Neither the name of the Nth Dimension nor the names of its contributors may
# be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# (c) Tim Brown, 2012
# <mailto:timb@nth-dimension.org.uk>
# <http://www.nth-dimension.org.uk/> / <http://www.machine.org.uk/>

use strict;

package UNIXSocketScanner::Response::nmap;

sub new {
	my $class;
	my $self;
	$class = shift;
	$self = {};
	bless($self, $class);
	$self->{'responsename'} = shift;
	$self->{'responsepattern'} = shift;
	return $self;
}

sub info {
	my $self;
	$self = shift;
	return $self->{'responsename'};
}

sub responsepattern {
	my $self;
	$self = shift;
	return $self->{'responsepattern'};
}

package UNIXSocketScanner::Probe;

sub new {
	my $class;
	my $self;
	$class = shift;
	$self = {};
	bless($self, $class);
	$self->{'probename'} = shift;
	$self->{'probestring'} = shift;
	$self->{'responsepattern'} = shift;
	return $self;
}

sub info {
	my $self;
	$self = shift;
	return $self->{'probename'};
}

sub probestring {
	my $self;
	$self = shift;
	return $self->{'probestring'};
}

sub responsepattern {
	my $self;
	$self = shift;
	return $self->{'responsepattern'};
}

package UNIXSocketScanner::Socket;

use Time::HiRes qw/ualarm/;
use IO::Socket::UNIX;

sub new {
	my $class;
	my $self;
	$class = shift;
	$self = {};
	bless($self, $class);
	$self->{'filename'} = shift;
	return $self;
}

sub info {
	my $self;
	$self = shift;
	return $self->{'filename'};
}

sub socketread {
	my $class;
	my $self;
	my $timeout;
	my $length;
	my $sockethandle;
	my $readdata;
	$self = shift;
        $timeout = shift;
        $length = shift;
        eval {
                local $SIG{ALRM} = sub {
                        die "UNIXSocketScanner::Exception::Host::SocketRead::IO::Socket::UNIX::Recv";
                };
                ualarm($timeout * 1000000);
		$sockethandle = $self->{'sockethandle'};
                $sockethandle->recv($readdata, $length);
                ualarm(0);

        };
        if ($@ =~ /UNIXSocketScanner::Exception::Host::SocketRead::IO::Socket::UNIX::Recv/) {
                return "";
        }
        return $readdata;
}

sub pipe {
	my $self;
	$self = shift;
	pipe($self->{'readhandle'}, $self->{'writehandle'});
}

sub check {
	my $self;
	my $probestring;
	my $verboseflag;
	my $sockethandle;
	my $responsestring;
	$self = shift;
	$probestring = shift;
	$verboseflag = shift;
	eval {
		local $SIG{ALRM} = sub {
			die "UNIXSocketScanner::Exception::Host::Check::IO::Socket::UNIX::New";
		};
                ualarm(1000000);
		$self->{'sockethandle'} = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $self->{'filename'});
                ualarm(0);
	};
	if ($@ ne "") {
		die $@;
	} else {
		eval {
			$sockethandle = $self->{'sockethandle'};
			defined($verboseflag) && print STDERR "sending '" . $probestring . "'\n";
			print $sockethandle $probestring;
			$responsestring = $self->socketread(1, 4096);
			defined($verboseflag) && print STDERR "received '" . (defined($responsestring) ? $responsestring : "") . "'\n";
			close($self->{'sockethandle'});
		};
		if ($@ eq "") {
			return $responsestring;
		}
	}
	return "";
}

sub writehandle {
	my $self;
	$self = shift;
	return $self->{'writehandle'};
}

sub readhandle {
	my $self;
	$self = shift;
	return $self->{'readhandle'};
}

sub unpipe {
	my $self;
	$self = shift;
	close($self->{'writehandle'});
}

sub parseresponses {
	my $self;
	my $probestring;
	my $verboseflag;
	my $responsetype;
	my $probename;
	my $responsestring;
	$self = shift;
	$probestring = shift;
	$verboseflag = shift;
	$probestring =~ s/\x0a//g;
	($responsetype, $probename, $responsestring) = split(/	/, $probestring);
	if ($responsetype eq "M") {
		$self->addmatch($probename);
	} else {
		if ($responsetype eq "T") {
			$self->addtrigger($probename, $responsestring);
		}
	}
	defined($verboseflag) && print STDERR "probe '" . $probename . "' @" . $self->info() . " responds with '" . (defined($responsestring) ? $responsestring : "") . "'\n";
}

sub addmatch {
	my $self;
	my $probename;
	my $response;
	$self = shift;
	$probename = shift;
	$self->{'matches'}{$probename} = 1;
}

sub addtrigger {
	my $self;
	my $probename;
	my $responsestring;
	$self = shift;
	$probename = shift;
	$responsestring = shift;
	$self->{'triggers'}{$probename} = $responsestring;
}

sub matches {
	my $self;
	$self = shift;
	return keys(%{$self->{'matches'}});
}

sub triggers {
	my $self;
	$self = shift;
	return keys(%{$self->{'triggers'}});
}

sub response {
	my $self;
	my $probename;
	$self = shift;
	$probename = shift;
	return $self->{'triggers'}{$probename};
}

package UNIXSocketScanner;

use File::Basename;
use Getopt::Std;
use Parallel::ForkManager;

my %argumentslist;
my $maximumprocess;
my $verboseflag;
my $probesfilename;
my $nmapprobesfilename;
my $forkmanager;
my $probeshandle;
my $parseflag;
my $probeline;
my $probename;
my $probestring;
my $responsepattern;
my $socketprobe;
my @socketprobes;
my $responsename;
my $socketresponse;
my $socketresponses;
my $filename;
my $targetsocket;
my @targetsockets;
my $processid;
my $writehandle;
my $responsestring;

sub main::HELP_MESSAGE {
	die "usage: find / -type s | " . basename($0) . " [-v] -x <maximumprocess> <-p <probesfilename> | -n <nmapprobesfilename>>

	-v - verbose mode, toggles realtime updates on STDERR";
}

sub main::VERSION_MESSAGE {
	print basename($0) . " 0.2\n";
}

$Getopt::Std::STANDARD_HELP_VERSION = 1;
getopts("vx:p:n:", \%argumentslist);
if (defined($argumentslist{'v'})) {
        $verboseflag = 1;
}
if (defined($argumentslist{'x'}) && ($argumentslist{'x'} =~ /([0-9]+)/)) {
	$maximumprocess = $1;
} else {
	Getopt::Std::help_mess("", "main");
}
if (defined($argumentslist{'p'}) && (-e $argumentslist{'p'})) {
	$probesfilename = $argumentslist{'p'};
}
if (defined($argumentslist{'n'}) && (-e $argumentslist{'n'})) {
	$nmapprobesfilename = $argumentslist{'n'};
}
if (!defined($probesfilename) && !defined($nmapprobesfilename)) {
	Getopt::Std::help_mess("", "main");
}

$forkmanager = Parallel::ForkManager->new($maximumprocess);
$forkmanager->run_on_finish(sub { 
	my $processid;
	my $returncode;
	my $targetsocket;
	my $readhandle;
	my $readdata;
	$processid = shift;
	$returncode = shift;
	$targetsocket = shift;
	$targetsocket->unpipe();
	$readhandle = $targetsocket->readhandle();
	while ($readdata = <$readhandle>) {
		$targetsocket->parseresponses($readdata, $verboseflag);
	}
	close($readhandle);
	print "I: " . $targetsocket->info() . " finished\n";
});
if (defined($probesfilename)) {
	open($probeshandle, "<" . $probesfilename);
	while ($probeline = <$probeshandle>) {
		$probeline =~ s/\x0a//g;
		if ($probeline =~ /^#/) {
			next;
		} else {
			($probename, $probestring, $responsepattern) = split(/	/, $probeline);
			$probestring =~ s/\\n/\x0a/g;
			$probestring =~ s/\\r/\x0d/g;
			$socketprobe = UNIXSocketScanner::Probe->new($probename, $probestring, $responsepattern);
			push(@socketprobes, $socketprobe);
		}
	}
	close($probeshandle);
}
if (defined($nmapprobesfilename)) {
	open($probeshandle, "<" . $nmapprobesfilename);
	$parseflag = 0;
	while ($probeline = <$probeshandle>) {
		if ($probeline =~ /^#/) {
			next;
		} else {
			if ($probeline =~ /^Probe UDP (.*?) q\|(.*)\|$/) {
				$parseflag = 0;
			} else {
				if ($probeline =~ /^Probe TCP (.*?) q\|(.*)\|$/) {
					$parseflag = 1;
					$probename = "nmap-probe-" . $1;
					$probestring = $2;
					$probestring =~ s/\\n/\x0a/g;
					$probestring =~ s/\\r/\x0d/g;
					$probestring =~ s/\\0/\x00/g;
					$probestring =~ s/\\x([0-9a-fA-F][0-9a-fA-F])/chr(hex($1))/eg;
					$responsepattern = "dummy";
					$socketprobe = UNIXSocketScanner::Probe->new($probename, $probestring, $responsepattern);
					push(@socketprobes, $socketprobe);
				} else {
					if ($parseflag == 1) {
						if ($probeline =~ /^match (.*?) m\|(.*?)\|.*/) {
							$responsename = "nmap-response-" . $1;
							$responsepattern = $2;
							$socketresponse = UNIXSocketScanner::Response::nmap->new($responsename, $responsepattern);
							push(@{$socketresponses->{$probename}}, $socketresponse);
						}
					}
				}
			}
		}
	}
	close($probeshandle);
}
while ($filename = <>) {
	$filename =~ s/\x0a//g;
	$targetsocket = UNIXSocketScanner::Socket->new($filename);
	push(@targetsockets, $targetsocket);
	$targetsocket->pipe();
	$processid = $forkmanager->start($targetsocket) and next;
	print "I: " . $targetsocket->info() . "\n";
	$writehandle = $targetsocket->writehandle();
	foreach $socketprobe (@socketprobes) {
		$responsestring = $targetsocket->check($socketprobe->probestring(), $verboseflag);
		$responsepattern = $socketprobe->responsepattern();
		if ($responsestring =~ /$responsepattern/s) {
			$responsestring =~ s/\x0a/\\n/g;
			$responsestring =~ s/\x0d/\\r/g;
			print $writehandle "M	" . $socketprobe->info() . "\n";
			print $writehandle "T	" . $socketprobe->info() . "	" . $responsestring . "\n";
		} else {
			# not a native match
			foreach $socketresponse (@{$socketresponses->{$socketprobe->info()}}) {
				$responsepattern = $socketresponse->responsepattern();
				if ($responsestring =~ /$responsepattern/s) {
					$responsestring =~ s/\x0a/\\n/g;
					$responsestring =~ s/\x0d/\\r/g;
					print $writehandle "M	" . $socketprobe->info() . "\n";
					print $writehandle "T	" . $socketprobe->info() . "	" . $responsestring . "\n";
					print $writehandle "M	" . $socketresponse->info() . "\n";
					print $writehandle "T	" . $socketresponse->info() . "	" . $responsestring . "\n";
				}
			}
		}
		if ($responsestring ne "") {
			$responsestring =~ s/\x0a/\\n/g;
			$responsestring =~ s/\x0d/\\r/g;
			print $writehandle "T	" . $socketprobe->info() . "	" . $responsestring . "\n";
		}
	}
	$forkmanager->finish();
}
$forkmanager->wait_all_children();
foreach $targetsocket (@targetsockets) {
	print $targetsocket->info() . "\n";
	foreach $probename ($targetsocket->matches()) {
		print "+ matches " . $probename . "\n";
	}
	if (defined($verboseflag)) {
		foreach $probename ($targetsocket->triggers()) {
			print "- " . $probename . " triggers " . $targetsocket->response($probename) . "\n";
		}
	}
}
exit(1);
