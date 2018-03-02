#!/usr/bin/perl

my $browser = LWP::UserAgent->new;
$browser->timeout(60);
$browser = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
$browser->protocols_allowed( [ 'http','https'] );



print "\n[+] Checking newest version\n";

my $response = $browser->get('http://raw.githubusercontent.com/rezasp/joomscan/master/version');

if($response->is_success){
	if($response->decoded_content =~ /$version/)
	{
		print "\n[!] New version available on http://github.com/rezasp/joomscan \n\n";
	}else
	{
		 print "\n[!] No new version available\n\n";

	}

}else{
	print "\nNetwork error!\n";
}