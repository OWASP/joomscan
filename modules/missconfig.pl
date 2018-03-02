#start missconfig check
$ctf=0;
dprint("Checking apache info/status files");
@configs = ('server-status','server-info');
foreach $config(@configs){
	$source=$ua->get("$target/$config")->decoded_content;
	if($source =~ m/Apache Server Information/i || $source =~ m/Server Root/i || $source =~ m/Apache Status/i){
		tprint("Interesting file is found \n$target/$config");
		$ctf=1;
	}
}
if($ctf==0){
	fprint("Readable info/status files are not found");
}

#end missconfig check