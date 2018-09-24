#!/usr/bin/perl

use utf8;
use open ':std', ':encoding(UTF-8)';
use Term::ANSIColor;

my $can_regexp=1;
eval "use Regexp::Common \"URI\"";
if($@) { $can_regexp=0; }

$ua = LWP::UserAgent->new();
$ua->protocols_allowed( [ 'http' ] );
if($target =~ /^https:\/\//) {
  my $can_https=1;
  eval "use LWP::Protocol::https";
  if($@) { $can_https=0; }

  if ($can_https) {
    $ua->ssl_opts( 'verify_hostname' => 0 );
    push @{ $ua->protocols_allowed }, 'https';
  } else {
    print color("red");
    print "[+] Target uses HTTPS, but module LWP::Protocol::https is not available!\n\n";
    print color("reset");
    exit (1);
  }
}

print color("blue");

$timeout = $timeout || 60;
$ua->timeout($timeout);

@weekday = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday");
($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();;
$year = $year + 1900;
$mon += 1;
$stime="$year-$mon-$mday $hour:$min:$sec $weekday[$wday]";


@uagnt=('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.5) Gecko/20060719 Firefox/1.5.0.5'
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
,'msnbot/1.1 (+http://search.msn.com/msnbot.htm)'
);

$agent = $agent || 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.5) Gecko/20060719 Firefox/1.5.0.5';

$agent = $uagnt[ rand @uagnt ] if($randomagent==1);

$ua->agent($agent);

if($proxy!=1){
    if($proxy =~ /^https?/ or $proxy =~ /^socks?/ or $proxy =~ /^ftp/){
        $ua->proxy([qw(http https)] => $proxy);
    }
}

$ua->cookie_jar({}) if($cookie!=1);
$ua->default_header('Cookie'=> "$cookie") if($cookie!=1);


our @dlog;our @tflog;

our $log="";
sub dprint{
    my ($in) = @_;
    $in =~ s/\/\//\//g;
    $in =~ s/http:\//http:\/\//g;
    $in =~ s/https:\//https:\/\//g;
    $#dlog++;
    $dlog[$#dlog]=$in;
    $in="\n[+] $in\n";
    $log .= $in;
    print color("blue");
    print "$in";
}
sub tprint{
    my ($in) = @_;
    $in =~ s/\/\//\//g;
    $in =~ s/http:\//http:\/\//g;
    $in =~ s/https:\//https:\/\//g;
    $#tflog++;
    $tflog[$#tflog]=$in;
    $in="[++] $in\n";
    $log .= $in;
    print color("yellow");
    print "$in";
    print color("blue");
}
sub fprint{
    my ($in) = @_;
    $in =~ s/\/\//\//g;
    $in =~ s/http:\//http:\/\//g;
    $in =~ s/https:\//https:\/\//g;
    $#tflog++;
    $tflog[$#tflog]="1337false$in";
    $in="[++] $in\n";
    $log .= $in;
    print color("red");
    print "$in";
    print color("blue");
}

print color("blue");
print "Processing $target ...\n\n\n";