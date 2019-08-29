#!/usr/bin/perl

use Term::ANSIColor;
 
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
    	
if(!defined $ARGV[0]){
 
    print color("cyan");
    printf "\n   Usage: 
    	joomscan.pl <target>
   	joomscan.pl -u http://target.com/joomla
      joomscan.pl -m targets.txt
   
   
      Options: 
   	joomscan.pl --help\n\n";
    print color("reset");
    exit(1);
}
$cookie=1;
$proxy=1;
#Start help Function
sub help
{
	print color("cyan");
	printf "   

Help :

Usage:	$0 [options]

--url | -u <URL>                |   The Joomla URL/domain to scan.
--mass | -m <filename>          |   Cycle through URLs provided in txt file
--enumerate-components | -ec    |   Try to enumerate components.
--joomla-version | -jv          |   Output target Joomla version and exit without further checks
--no-report | -nr               |   Do not produce a report  

--cookie <String>               |   Set cookie.
--user-agent | -a <User-Agent>  |   Use the specified User-Agent.
--random-agent | -r             |   Use a random User-Agent.
--timeout <Time-Out>            |   Set timeout.
--proxy=PROXY                   |   Use a proxy to connect to the target URL
           Proxy example: --proxy http://127.0.0.1:8080
                                  https://127.0.0.1:443
                                  socks://127.0.0.1:414
                       
--about                         |   About Author
--update                        |   Update to the latest version.
--help | -h                     |   This help screen.
--version                       |   Output the current joomscan version and exit.


";
	print color("reset");
	exit(1);
}
sub about
{
	print color("cyan");
	printf "
   Author         :   $author
   Twitter        :   \@rezesp , \@Ali_Razmjo0
   Git repository :   https://github.com/rezasp/joomscan/
   Issues         :   https://github.com/rezasp/joomscan/issues
    \n\n";
	print color("reset");
	exit(1);
}
sub update
{
    do "$mepath/core/update.pl";
	print color("reset");
	exit(1);
}


GetOptions(
  'help|h' => sub { help(0) },
  'update' => sub { update(0) },
  'about' => sub { about(0) },
  'enumerate-components|ec'   => sub { $components = 1 },
  'no-report|nr' => sub { $noreport = 1 },
  'joomla-version|jv' => sub { $jversion = 1 },
  'random-agent|r'   => sub { $randomagent = 1 },
  'user-agent|a=s' => \$agent,
  'timeout=s' => \$timeout,
  'proxy=s' => \$proxy,
  'cookie=s' => \$cookie,
  'u|url=s' => \$target,
  'm|mass=s' => \$urlfile,
  'version' => sub { print "\n\nVersion : $version\n\n";exit; },

);
if(($target !~ /\S/)&&($urlfile !~ /\S/)){
  print color("red");
  print "[+] No target specified!\n\n";
  print color("reset");
  exit (1);
}
if($target !~ /^https?:\/\//) { $target = "http://$target"; };

#End help Function
