#start WAF Detector
$fwtf=0;
$source=$ua->get("$target/")->headers_as_string;
dprint("FireWall Detector");
if ($source =~ /cloudflare-nginx/g or $source =~ /CF-Chl-Bypass/g or $source =~ /Server\: cloudflare/g) {
	tprint("Firewall detected : CloudFlare");
	$fwtf=1;
}elsif ($source =~ /incapsula/g) {
	tprint("Firewall detected : Incapsula");
	$fwtf=1;
}elsif ($source =~ /ShieldfyWebShield/g) {
	tprint("Firewall detected : Shieldfy");
	$fwtf=1;
}

$source=$ua->get("$target/../../etc")->headers_as_string;
if ($source =~ /Mod_Security/g) {
	tprint("Firewall detected : Mod_Security");
	$fwtf=1;
}
if ($fwtf==0){
	fprint("Firewall not detected");
}
#end WAF Detector
