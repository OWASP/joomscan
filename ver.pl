#start Version finder
dprint("Detecting Joomla Version");

$ua->timeout(60);

my $response = $ua->get("$target");
if (!$response->is_success) {
    print color("red");
    print "[++] The target is not alive!\n\n";
    print color("reset");
    if (!$urlfile) {exit 0;} else {next;}
}

$ua->timeout($timeout);

$source=$ua->get("$target/")->as_string;
if($source =~ /X-Meta-Generator\:(.*?)\n/){
$ppp=$1;
    if($ppp =~ /[0-9]+(\.[0-9]+)+/g){
        $ver="Joomla $&";
    }
}
if($ver !~ m/\./i){
    @vers = ('administrator/manifests/files/joomla.xml','language/en-GB/en-GB.xml','administrator/components/com_content/content.xml','administrator/components/com_plugins/plugins.xml','administrator/components/com_media/media.xml','mambots/content/moscode.xml');
    foreach $verc(@vers){
            $source=$ua->get("$target/$verc")->decoded_content;
            if($source =~ /\<version\>(.*?)\<\/version\>/){
                $ver="Joomla $1";
                last;
            }
    }
}
if($ver !~ m/\./i){
    @vers = ('language/en-GB/en-GB.xml','templates/system/css/system.css','media/system/js/mootools-more.js','language/en-GB/en-GB.ini','htaccess.txt','language/en-GB/en-GB.com_media.ini');
    foreach $verc(@vers){
            $source=$ua->get("$target/$verc")->decoded_content;
            if($source =~ /system\.css 20196 2011\-01\-09 02\:40\:25Z ian/ or $source =~ /MooTools\.More\=\{version\:\"1\.3\.0\.1\"/ or $source =~ /en-GB\.ini 20196 2011\-01\-09 02\:40\:25Z ian/ or $source =~ /en-GB\.ini 20990 2011\-03\-18 16\:42\:30Z infograf768/ or $source =~ /20196 2011\-01\-09 02\:40\:25Z ian/){
                $ver="Joomla 1.6";
                last;
            }elsif($source =~ /system\.css 21322 2011\-05\-11 01\:10\:29Z dextercowley / or $source =~ /MooTools\.More\=\{version\:\"1\.3\.2\.1\"/ or $source =~ /22183 2011\-09\-30 09\:04\:32Z infograf768/ or $source =~ /21660 2011\-06\-23 13\:25\:32Z infograf768/){
                $ver="Joomla 1.7";
                last;
            }elsif($source =~ /Joomla! 1.5/ or $source =~ /MooTools\=\{version\:\'1\.12\'\}/ or $source =~ /11391 2009\-01\-04 13\:35\:50Z ian/){
                $ver="Joomla 1.5";
                last;
            }elsif($source =~ /Copyright \(C\) 2005 \- 2012 Open Source Matters/ or $source =~ /MooTools.More\=\{version\:\"1\.4\.0\.1\"/){
                $ver="Joomla 2.5";
                last;
            }elsif($source =~ /<meta name=\"Keywords\" content=\"(.*?)\">\s+<meta name/){
                $ver="Joomla $1";
                last;
            }elsif($source =~ /(Copyright \(C\) 2005 - 200(6|7))/ or $source =~ /47 2005\-09\-15 02\:55\:27Z rhuk/ or $source =~ /423 2005\-10\-09 18\:23\:50Z stingrey/ or $source =~ /1005 2005\-11\-13 17\:33\:59Z stingrey/ or $source =~ /1570 2005\-12\-29 05\:53\:33Z eddieajau/ or $source =~ /2368 2006\-02\-14 17\:40\:02Z stingrey/ or $source =~ /1570 2005\-12\-29 05\:53\:33Z eddieajau/ or $source =~ /4085 2006\-06\-21 16\:03\:54Z stingrey/ or $source =~ /4756 2006\-08\-25 16\:07\:11Z stingrey/ or $source =~ /5973 2006\-12\-11 01\:26\:33Z robs/ or $source =~ /5975 2006\-12\-11 01\:26\:33Z robs/){
            $ver="Joomla 1.0";
                    last;
            }        
    }
}

if($ver !~ m/\./i){
    $source=$ua->get("$target/README.txt")->decoded_content;
    if($source =~ /package to version (.*?)\n/){
        $ver="Joomla $1";
    }
}

$ver =~ tr/[0-9][a-z][A-Z][\.]\ //cd;
#if( $ver =~ /\d\.\d\.\d+/ and length($ver) > 25) {$ver= "Joomla $&";}  

if($ver !~ m/\./i){fprint("ver 404\n")}else{tprint("$ver");}
 
#end Version finder
