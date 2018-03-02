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


$author="Mohammad Reza Espargham , Ali Razmjoo";$author.="";
$version="0.0.1";$version.="";
$codename="ReBorn";$codename.="";
$update="2018/03/03";$update.="";
$mmm=0;

system(($^O eq 'MSWin32') ? 'cls' : 'clear');
use if $^O eq "MSWin32", Win32::Console::ANSI;
use Term::ANSIColor;
use Getopt::Long;
use LWP::UserAgent;
use LWP::Simple;


$SIG{INT} = \&interrupt;
sub interrupt {
    fprint("\nShutting Down , Interrupt by user");
    do "./core/report.pl";
    print color("reset");
    exit 0;
}
do "./core/header.pl";
do "./core/main.pl";
do "./core/ver.pl";
do "./exploit/verexploit.pl";
do "./modules/pathdisclure.pl";
do "./modules/debugmode.pl";
do "./modules/dirlisting.pl";
do "./modules/missconfig.pl";
do "./modules/cpfinder.pl";
do "./modules/robots.pl";
do "./modules/backupfinder.pl";
do "./modules/errfinder.pl";
do "./modules/reg.pl";
do "./modules/configfinder.pl";
do "./exploit/components.pl" if($components==1);

do "./core/report.pl";
print color("reset");
