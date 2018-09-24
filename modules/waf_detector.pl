#start WAF Detector
$fwtf=0;
$source=$ua->get("$target/")->headers_as_string;
dprint("FireWall Detector");
if ($source =~ /cloudflare-nginx/g or $source =~ /CF-Chl-Bypass/g or $source =~ /Server\: cloudflare/g or $source =~ /__cfduid/g ) {
	tprint("Firewall detected : CloudFlare");
	$fwtf=1;
}elsif ($source =~ /incapsula/g or $source =~ /incap_ses/g or $source =~ /visid_incap/g or $source =~ /visid_incap/g) {
	tprint("Firewall detected : Incapsula");
	$fwtf=1;
}elsif ($source =~ /ShieldfyWebShield/g) {
	tprint("Firewall detected : Shieldfy");
	$fwtf=1;
}elsif ($source =~ /X\-Sucuri\-ID/g) {
	tprint('Firewall detected : Sucuri Firewall (Sucuri Cloudproxy)');
	$fwtf=1;
}elsif ($source =~ /X\-Powered\-By\-Anquanbao/g) {
	tprint('Firewall detected : Anquanbao');
	$fwtf=1;
}elsif ($source =~ /barra_counter_session/g or $source =~ /BNI__BARRACUDA_LB_COOKIE/g or $source =~ /BNI_persistence/g) {
	tprint('Firewall detected : Barracuda Application Firewall');
	$fwtf=1;
}elsif ($source =~ /BinarySec/g or $source =~ /x-binarysec-via/g or $source =~ /x-binarysec-nocache/g) {
	tprint('Firewall detected : BinarySec');
	$fwtf=1;
}elsif ($source =~ /BlockDos\.net/g) {
	tprint('Firewall detected : BlockDoS');
	$fwtf=1;
}elsif ($source =~ /Powered\-By\-ChinaCache/g) {
	tprint('Firewall detected : ChinaCache-CDN');
	$fwtf=1;
}elsif ($source =~ /ACE XML Gateway/g) {
	tprint('Firewall detected : Cisco ACE XML Gateway');
	$fwtf=1;
}elsif ($source =~ /Protected by COMODO WAF/g) {
	tprint('Firewall detected : Comodo WAF');
	$fwtf=1;
}elsif ($source =~ /X\-dotDefender\-denied/g) {
	tprint('Firewall detected : Applicure dotDefender');
	$fwtf=1;
}elsif ($source =~ /BigIP|BIG-IP|BIGIP/g or $source =~ /LastMRH_Session/g or $source =~ /MRHSequence/g) {
	tprint('Firewall detected : F5 BIG-IP APM');
	$fwtf=1;
}elsif ($source =~ /F5\-TrafficShield/g) {
	tprint('Firewall detected : F5 Trafficshield');
	$fwtf=1;
}elsif ($source =~ /FORTIWAFSID/g) {
	tprint('Firewall detected : FortiWeb');
	$fwtf=1;
}elsif ($source =~ /Mission Control Application Shield/g) {
	tprint('Firewall detected : Mission Control Application Shield');
	$fwtf=1;
}elsif ($source =~ /naxsi/g) {
	tprint('Firewall detected : Naxsi');
	$fwtf=1;
}elsif ($source =~ /NCI\_\_SessionId/g) {
	tprint('Firewall detected : NetContinuum');
	$fwtf=1;
}elsif ($source =~ /pwcount/g or $source =~ /ns\_af/g or $source =~ /citrix\_ns\_id/g  or $source =~ /NSC\_/g ) {
	tprint('Firewall detected : Citrix NetScaler');
	$fwtf=1;
}elsif ($source =~ /NSFocus/g ) {
	tprint('Firewall detected : NSFocus');
	$fwtf=1;
}elsif ($source =~ /PowerCDN/g ) {
	tprint('Firewall detected : PowerCDN');
	$fwtf=1;
}elsif ($source =~ /profense/g ) {
	tprint('Firewall detected : Profense');
	$fwtf=1;
}elsif ($source =~ /X\-SL\-CompState/g ) {
	tprint('Firewall detected : Radware AppWall');
	$fwtf=1;
}elsif ($source =~ /Safedog/g or $source =~ /safedog/g ) {
	tprint('Firewall detected : Safedog');
	$fwtf=1;
}elsif ($source =~ /st8id/g) {
	tprint('Firewall detected : Teros WAF');
	$fwtf=1;
}elsif ($source =~ /Secure Entry Server/g) {
	tprint('Firewall detected : USP Secure Entry Server');
	$fwtf=1;
}elsif ($source =~ /nginx-wallarm/g) {
	tprint('Firewall detected : Wallarm');
	$fwtf=1;
}elsif ($source =~ /WT263CDN/g) {
	tprint('Firewall detected : West263CDN');
	$fwtf=1;
}elsif ($source =~ /X-Powered-By-360WZB/g) {
	tprint('Firewall detected : 360WangZhanBao');
	$fwtf=1;
}


$source=$ua->get("$target/../../etc")->headers_as_string;
if ($source =~ /mod_security/g or $source =~ /Mod_Security/g or $source =~ /NOYB/g) {
	tprint("Firewall detected : Mod_Security");
	$fwtf=1;
}
if ($fwtf==0){
	fprint("Firewall not detected");
}
#end WAF Detector