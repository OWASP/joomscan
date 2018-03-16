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

# TODO make it work on windows again
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


my @uagnt_labels= ('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.5) Gecko/20060719 Firefox/1.5.0.5'
		   ,'Googlebot/2.1 ( http://www.googlebot.com/bot.html)'
		   ,'Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.13 (KHTML, like Gecko) Ubuntu/10.04 Chromium/9.0.595.0 Chrome/9.0.595.0 Safari/534.13'
		   ,'Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.2; WOW64; .NET CLR 2.0.50727)'
		   ,'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51'
		   ,'Mozilla/5.0 (compatible; 008/0.83; http://www.80legs.com/webcrawler.html) Gecko/2008032620'
		   ,'Debian APT-HTTP/1.3 (0.8.10.3)'
		   ,'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
		   ,'Googlebot/2.1 (+http://www.googlebot.com/bot.html)'
		   ,'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)'
		   ,'YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)'
		   ,'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)'
		   ,'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'
		   ,'msnbot/1.1 (+http://search.msn.com/msnbot.htm)');

sub create_user_agent {
  my $agent_label = shift || 'random';
  my $cookie = shift;
  my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
  $ua->protocols_allowed(['http','https']);
  if($agent_label eq 'random'){
    $agent_label = $uagnt_labels[rand(@uagnt_labels)];
  }
  $ua->agent($agent_label);
  if($cookie){
    $ua->cookie_jar({});
    $ua->default_header('Cookie' => $cookie);
  }
  return $ua;
}

sub print_with_color {
  my ($color, $fn, @params) = @_;
  print(color($color));
  $fn->(@params);
  print(color(reset));
}

sub with_color_str {
  my ($color, $fn, @params) = @_;
  return color($color). $fn->(@params) . color("reset");
}

sub partial {
  my ($fn, @args) = @_;
  sub {
    $fn->(@args, @_);
  }
}

sub banner {
  print color("YELLOW");
  print q{
    ____  _____  _____  __  __  ___   ___    __    _  _
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  (
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
};
  print color("red") . "\t\t\t(1337.today)" . color("reset");
  print "

    --=[". color("BLUE") . "OWASP JoomScan". color("reset") ."
    +---++---==[Version : "
   	. color("red"). "$version\n". color("reset") . "    +---++---==[Update Date : [". color("red") . "$update". color("reset") . "]
    +---++---==[Authors : ". color("red") . "$author". color("reset")."
    --=[Code name : ". color("red") . "$codename". color("reset")."\n    \@OWASP_JoomScan , \@rezesp , \@Ali_Razmjo0 , \@OWASP\n\n";
}


sub usage {
  print <<EOF
Usage:
 joomscan.pl <target>
 joomscan.pl -u http://target.com/joomla
Options:
 joomscan.pl --help

EOF
;
  exit(0);
}


sub help
{
  print <<EOF
Help :

Usage:	$0 [options]

--url | -u <URL>                |   The Joomla URL/domain to scan.
--enumerate-components | -ec    |   Try to enumerate components.

--cookie <String>               |   Set cookie.
--user-agent | -a <User-Agent>  |   Use the specified User-Agent.
--random-agent | -r             |   Use a random User-Agent.
--timeout <Time-Out>            |   Set timeout.
--about                         |   About Author
--update                        |   Update to the latest version.
--help | -h                     |   This help screen.
--version                       |   Output the current version and exit.
EOF
;
  exit(0);
}

sub about
{
print <<'EOF'
Author         :   $author
Twitter        :   @rezesp , @Ali_Razmjo0
Git repository :   https://github.com/rezasp/joomscan/
Issues         :   https://github.com/rezasp/joomscan/issues

EOF
;
  exit(0);
}

sub update
{
  #FIXME
    do "$mepath/core/update.pl";
}

my $enum_components = 0;
my $use_random_agent = 0;
my $agent = undef;
my $timeout = 60;
my $cookie = "";
my $target = "";

my $with_cyan = partial(\&print_with_color, 'cyan');

GetOptions(
  'help|h' => partial($with_cyan, \&help),
  'update' => \&update,
  'about' => \&about,
  'enumerate-components|ec' => \$enum_components,
  'random-agent|r'   => \$use_random_agent,
  'user-agent|a=s' => \$agent,
  'timeout=s' => \$timeout,
  'cookie=s' => \$cookie,
  'u|url=s' => \$target,
  'version' => sub { print "\n\nVersion : $version\n\n";exit; }
);


banner();

if(!$target){
  usage();
}

if($target !~ /http/) {
  $target = "http://$target";
}

my $ua;

if($agent){
  $ua = create_user_agent($agent, $cookie);
}
elsif($use_random_agent){
  $ua = create_user_agent('random', $cookie);
}
else{
  $ua = create_user_agent($uagnt_labels[0], $cookie);
}

JoomScan::Check::check_reg($ua, $target);
JoomScan::Check::check_robots_txt($ua, $target);
JoomScan::Check::check_path_disclosure($ua, $target);
JoomScan::Check::check_misconfiguration($ua, $target);
JoomScan::Check::check_error_logs($ua, $target);
JoomScan::Check::check_dirlisting($ua, $target);
JoomScan::Check::check_debug_mode($ua, $target);
JoomScan::Check::check_admin_pages($ua, $target);
JoomScan::Check::check_backups($ua, $target);
JoomScan::Check::check_configs($ua, $target);

END{ print color("reset"); }
