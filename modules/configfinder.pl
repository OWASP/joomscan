#start config.php.x check

$ctf=0;
dprint("Checking sensitive config.php.x file");
@configs = ('configuration.php~','configuration.php.new','configuration.php.new~','configuration.php.old','configuration.php.old~','configuration.bak','configuration.php.bak','configuration.php.bkp','configuration.txt','configuration.php.txt','configuration - Copy.php','configuration.php.swo','configuration.php_bak','configuration.php#','configuration.orig','configuration.php.save','configuration.php.original','configuration.php.swp','configuration.save','.configuration.php.swp','configuration.php1','configuration.php2','configuration.php3','configuration.php4','configuration.php4','configuration.php6','configuration.php7','configuration.phtml','configuration.php-dist');

my $cnftmp="";
foreach $config(@configs){
    $source=$ua->get("$target/$config")->decoded_content;
    if($source =~ m/public \$ftp_pass/i || $source =~ m/\$dbtype/i || $source =~ m/force_ssl/i || $source =~ m/mosConfig_secret/i || $source =~ m/mosConfig_dbprefix/i ){
        $cnftmp="$cnftmp\Readable config file is found \n config file path : $target/$config\n";
        $ctf=1;
    }
}
if($ctf==0){
    fprint("Readable config files are not found");
}else{
    tprint($cnftmp);
}
#end config.php.x check
