#!/usr/bin/perl
#
#            --------------------------------------------------
#                            OWASP JoomScan
#            --------------------------------------------------
#        Copyright (C) <2017>
#
#        This program is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        any later version.
#
#        This program is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
use warnings;
use strict;

# TODO make it work on windows
# system(($^O eq 'MSWin32') ? 'cls' : 'clear');
# use if $^O eq "MSWin32", Win32::Console::ANSI;
use Term::ANSIColor;
use Getopt::Long;
use LWP::UserAgent;
use LWP::Simple;
use Cwd;

use JoomScan::Check qw(check_reg check_robots_txt check_path_disclosure
		    check_misconfiguration check_error_logs
		    check_dirlisting check_debug_mode
		    check_admin_pages check_backups check_configs);

my $mepath = Cwd::realpath($0); $mepath =~ s#/[^/\\]*$##;

$SIG{INT} = \&interrupt;
sub interrupt {
    fprint("\nShutting Down , Interrupt by user");
    do "$mepath/core/report.pl";
    print color("reset");
    exit 0;
}


my $author="Mohammad Reza Espargham , Ali Razmjoo";$author.="";
my $version="0.0.1";$version.="";
my $codename="ReBorn";$codename.="";
my $update="2018/03/03";$update.="";
my $mmm=0;


my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
$ua->protocols_allowed( ['http','https'] );
my $target = "fnord";

check_reg($ua, $target);
check_robots_txt($ua, $target);
check_path_disclosure($ua, $target);
check_misconfiguration($ua, $target);
check_error_logs($ua, $target);
check_dirlisting($ua, $target);
check_debug_mode($ua, $target);
check_admin_pages($ua, $target);
check_backups($ua, $target);
check_configs($ua, $target);

print color("reset");
