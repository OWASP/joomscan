#start Directory Listing

$ctf=0;
@dirl = ('administrator/components','components','administrator/modules','modules','administrator/templates','templates','cache','images','includes','language','media','templates','tmp','images/stories','images/banners');

my $cnftmp="";
foreach $dir(@dirl){
	$source=$ua->get("$target/$dir/")->decoded_content;
	if ($source =~ /<title>Index of/g or $source =~ /Last modified<\/a>/g) {
		$cnftmp="$cnftmp$target/$dir\n";
		$ctf=1;
	}
}
if($ctf==1){
	dprint("Checking Directory Listing");
	tprint("directory has directory listing : \n$cnftmp");
}

#end Directory Listing
