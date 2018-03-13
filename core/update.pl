#!/usr/bin/perl

my $can_https=1;
eval "use LWP::Protocol::https";
if($@) { $can_https=0; }

if (!$can_https) {
  print color("red");
  print "[+] Update requires HTTPS, but module LWP::Protocol::https is not available!\n\n";
  print color("reset");
  exit (1);
}

my $browser = LWP::UserAgent->new;
$browser->timeout(60);
$browser = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
$browser->protocols_allowed( [ 'http','https'] );



print "\n[+] Checking newest version\n";

my $response = $browser->get('https://raw.githubusercontent.com/rezasp/joomscan/master/version');

if($response->is_success){
	if($response->decoded_content !~ /$version/)
	{
		print "\n[!] New version available on https://github.com/rezasp/joomscan/releases/latest\n\n";
	}else
	{
		 print "\n[!] No new version available\n\n";

	}

}else{
	print "\nNetwork error!\n";
}
