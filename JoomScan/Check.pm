package JoomScan::Check;
use JoomScan::Logging qw(dprint tprint fprint)
use warnings;
use strict;

sub check_reg {
  my ($ua, $target) = @_;
  my $source=$ua->get("$target/index.php?option=com_users&view=registration")->decoded_content;
  if ($source =~ /registration.register/g or
      $source =~ /jform_password2/g or $source =~ /jform_email2/g) {
    dprint("Checking user registration");
    tprint("registration is enabled\n$target/index.php?option=com_users&view=registration");
  }
}

sub check_robots_txt {
  my ($ua, $target) = @_;
  # dprint("Checking robots.txt existing");
  my $response=$ua->get("$target/robots.txt");
  my $headers  = $response->headers();
  my $content_type =$headers->content_type();
  if ($response->status_line =~ /200/g and
      $content_type =~ /text\/plain/g) {
    my $source = $response->decoded_content;
    my @lines = split /\n/, $source;
    my $probot="";
    foreach my $line( @lines ) {
      if($line =~ /llow:/g){
        my $between=substr($line, index($line, ': ')+2, 99999);
        $probot.="$target$between\n";
      }
    }
    tprint("robots.txt is found\npath : $target/robots.txt \n\nInteresting path found from robots.txt\n$probot");
  }else{
    fprint("robots.txt is not found");
  }
}

#start path disclosure

sub check_path_disclosure {
  my ($ua, $target) = @_;
  my @plinks = ("mambo/mambots/editors/mostlyce/jscripts/tiny_mce/plugins/spellchecker/classes/PSpellShell.php","components/com_docman/dl2.php?archive=0&file=","libraries/joomla/utilities/compat/php50x.php","libraries/joomla/client/ldap.php","libraries/joomla/html/html/content.php","libraries/phpmailer/language/phpmailer.lang-joomla.php","libraries/phpxmlrpc/xmlrpcs.php","libraries/joomla/utilities/compat/php50x.php","index.php?option=com_jotloader&section[]=","index.php?option=com_jotloader&section[]=",'plugins/content/clicktocall/clicktocall.php','/index.php?option=com_remository&Itemid=53&func=[]select&id=5');
  foreach my $plink (@plinks){
    my $source=$ua->get("$target/$plink")->decoded_content;
    if($source =~ m/Cannot modify header information/i || $source =~ m/trim()/i || $source =~ m/header already sent/i || $source =~ m/Fatal error/i || $source =~ m/errno/i || $source =~ m/Warning: /i){
      my $pathdis="";
      my $source =~ /array given in (.*?) on line/;
      $pathdis=$1;
      if($pathdis !~ ""){
        $source =~ /array given in (.*?) on line /;
        $pathdis=$1;
      }
      if($pathdis !~ ""){
        $source =~ /occurred in (.*?) in line /;
        $pathdis=$1;
      }
      if($pathdis !~ ""){
        $source =~ /occurred in (.*?) on line/;
        $pathdis=$1;
      }
      if($pathdis !~ ""){
        $source =~ /on a non-object in (.*?) on line/;
        $pathdis=$1;
      }
      if($pathdis !~ ""){
        $source =~ /on a non-object in (.*?) in line/;
        $pathdis=$1;
      }
      if($pathdis !~ ""){
        $source =~ /No such file or directory (errno 2) in (.*?) on line/;
        $pathdis=$1;
      }
      if($pathdis !~ ""){
        $source =~ /No such file or directory in (.*?) in line/;
        $pathdis=$1;
      }
      if($pathdis !~ ""){
        $source =~ /not found in (.*?) in line/;
        $pathdis=$1;
      }
      if($pathdis !~ ""){
        $source =~ /not found in (.*?) on line/;
        $pathdis=$1;
      }
      $pathdis =~ s/<b>//g;
      $pathdis =~ s/<\/b>//g;
      $pathdis =~ s/<strong>//g;
      $pathdis =~ s/<\/strong>//g;
      dprint("Full Path Disclosure (FPD)");
      tprint("Full Path Disclosure (FPD) in '$target/$plink' : $pathdis\n");
      last;
    }
  }
}

sub check_missconfiguration {
  my ($ua, $target) = @_;
  my $ctf=0;
  dprint("Checking apache info/status files");
  my @configs = ('server-status','server-info');
  foreach my $config (@configs){
    my $source = $ua->get("$target/$config")->decoded_content;
    if($source =~ m/Apache Server Information/i || $source =~ m/Server Root/i || $source =~ m/Apache Status/i){
      tprint("Interesting file is found \n$target/$config");
      $ctf=1;
    }
  }
  if($ctf==0){
    fprint("Readable info/status files are not found");
  }
}

sub check_error_logs {
  my ($ua, $target) = @_;
  dprint("Finding common log files name");
  my $ertf=0;
  my @error = ('error.log','error_log','php-scripts.log','php.errors','php5-fpm.log','php_errors.log','debug.log');
  foreach my $er (@error){
    if (my ($content_type, $doc_length, $mod_time, $expires, $server) =head("$target/$er")){
      if($content_type !~ m/text\/html/i){
        tprint("$er path :  $target/$er\n");
        $ertf=1;
      }
    }
  }
  if($ertf==0) {
    fprint("error log is not found");
  }
}


sub check_dirlisting{
  my ($ua, $target) = @_;
  my $ctf=0;
  my @dirl = ('administrator/components','components','administrator/modules','modules','administrator/templates','templates','cache','images','includes','language','media','templates','tmp','images/stories','images/banners');
  my $cnftmp="";
  foreach my $dir(@dirl){
    my $source = $ua->get("$target/$dir/")->decoded_content;
    if ($source =~ /<title>Index of/g or $source =~ /Last modified<\/a>/g) {
      $cnftmp="$cnftmp$target/$dir\n";
      $ctf=1;
    }
  }
  if($ctf==1){
    dprint("Checking Directory Listing");
    tprint("directory has directory listing : \n$cnftmp");
  }
}

sub check_debug_mode {
  my ($ua, $target) = @_;
  my $source = $ua->get("$target/")->decoded_content;
  if ($source =~ /Joomla\! Debug Console/g or $source =~ /xdebug\.org\/docs\/all_settings/g) {
    dprint("Checking Debug Mode status");
    tprint("Debug mode Enabled : $target/");
  }
}

sub check_admin_pages {
  my ($ua, $target) = @_;
  dprint("admin finder");
  my $amtf=0;
  my $adming = "";
  my @admins = ('administrator','admin','panel','webadmin','modir','manage','administration','joomla/administrator','joomla/admin');
  foreach my $admin (@admins){
    my $source = $ua->get("$target/$admin/");
    if($source->code=~/200/ or $source->code=~/403/ or $source->code=~/500/ or $source->code=~/501/){
      $amtf=1;
      $adming=$admin;
      last;
    }
  }
  if($amtf==1){
    tprint("Admin page : $target/$adming/");
  }else{
    fprint("Admin page not found");
  }
}

sub check_backups {
  my ($ua, $target) = @_;
  my $btf=0;
  dprint("Finding common backup files name");
  my @backups = ('1.txt','2.txt','1.gz','1.rar','1.save','1.tar','1.tar.bz2','1.tar.gz','1.tgz','1.tmp','1.zip','2.back','2.backup','2.gz','2.rar','2.save','2.tar','2.tar.bz2','2.tar.gz','2.tgz','2.tmp','2.zip','backup.back','backup.backup','backup.bak','backup.bck','backup.bkp','backup.copy','backup.gz','backup.old','backup.orig','backup.rar','backup.sav','backup.save','backup.sql~','backup.sql.back','backup.sql.backup','backup.sql.bak','backup.sql.bck','backup.sql.bkp','backup.sql.copy','backup.sql.gz','backup.sql.old','backup.sql.orig','backup.sql.rar','backup.sql.sav','backup.sql.save','backup.sql.tar','backup.sql.tar.bz2','backup.sql.tar.gz','backup.sql.tgz','backup.sql.tmp','backup.sql.txt','backup.sql.zip','backup.tar','backup.tar.bz2','backup.tar.gz','backup.tgz','backup.txt','backup.zip','database.back','database.backup','database.bak','database.bck','database.bkp','database.copy','database.gz','database.old','database.orig','database.rar','database.sav','database.save','database.sql~','database.sql.back','database.sql.backup','database.sql.bak','database.sql.bck','database.sql.bkp','database.sql.copy','database.sql.gz','database.sql.old','database.sql.orig','database.sql.rar','database.sql.sav','database.sql.save','database.sql.tar','database.sql.tar.bz2','database.sql.tar.gz','database.sql.tgz','database.sql.tmp','database.sql.txt','database.sql.zip','database.tar','database.tar.bz2','database.tar.gz','database.tgz','database.tmp','database.txt','database.zip','joom.back','joom.backup','joom.bak','joom.bck','joom.bkp','joom.copy','joom.gz','joomla.back','Joomla.back','joomla.backup','Joomla.backup','joomla.bak','Joomla.bak','joomla.bck','Joomla.bck','joomla.bkp','Joomla.bkp','joomla.copy','Joomla.copy','joomla.gz','Joomla.gz','joomla.old','Joomla.old','joomla.orig','Joomla.orig','joomla.rar','Joomla.rar','joomla.sav','Joomla.sav','joomla.save','Joomla.save','joomla.tar','Joomla.tar','joomla.tar.bz2','Joomla.tar.bz2','joomla.tar.gz','Joomla.tar.gz','joomla.tgz','Joomla.tgz','joomla.zip','Joomla.zip','joom.old','joom.orig','joom.rar','joom.sav','joom.save','joom.tar','joom.tar.bz2','joom.tar.gz','joom.tgz','joom.zip','site.back','site.backup','site.bak','site.bck','site.bkp','site.copy','site.gz','site.old','site.orig','site.rar','site.sav','site.save','site.tar','site.tar.bz2','site.tar.gz','site.tgz','site.zip','sql.zip.back','sql.zip.backup','sql.zip.bak','sql.zip.bck','sql.zip.bkp','sql.zip.copy','sql.zip.gz','sql.zip.old','sql.zip.orig','sql.zip.save','sql.zip.tar','sql.zip.tar.bz2','sql.zip.tar.gz','sql.zip.tgz','upload.back','upload.backup','upload.bak','upload.bck','upload.bkp','upload.copy','upload.gz','upload.old','upload.orig','upload.rar','upload.sav','upload.save','upload.tar','upload.tar.bz2','upload.tar.gz','upload.tgz','upload.zip');
  foreach my $back (@backups){
    if (my ($content_type, $doc_length, $mod_time, $expires, $server) =head("$target/$back")){
      if($content_type !~ m/text\/html/i){
        tprint("Backup file is found \nPath : $target/$back\n");
        $btf=1;
      }
    }
  }
  if($btf==0){
    fprint("Backup files are not found");
  }
}

sub check_configs{
  my ($ua, $target) = @_;
  #start config.php.x check

  my $ctf=0;
  dprint("Checking sensitive config.php.x file");
  my @configs = ('configuration.php~','configuration.php.new','configuration.php.new~','configuration.php.old','configuration.php.old~','configuration.bak','configuration.php.bak','configuration.php.bkp','configuration.txt','configuration.php.txt','configuration - Copy.php','configuration.php.swo','configuration.php_bak','configuration.php#','configuration.orig','configuration.php.save','configuration.php.original','configuration.php.swp','configuration.save','.configuration.php.swp','configuration.php1','configuration.php2','configuration.php3','configuration.php4','configuration.php4','configuration.php6','configuration.php7','configuration.phtml','configuration.php-dist');

  my $cnftmp="";
  foreach my $config (@configs){
    my $source = $ua->get("$target/$config")->decoded_content;
    if($source =~ m/public \$ftp_pass/i || $source =~ m/\$dbtype/i || $source =~ m/force_ssl/i || $source =~ m/mosConfig_secret/i || $source =~ m/mosConfig_dbprefix/i ){
      $cnftmp="$cnftmp Readable config file is found \n config file path : $target/$config\n";
      $ctf=1;
    }
  }
  if($ctf==0){
    fprint("Readable config files are not found");
  }else{
    tprint($cnftmp);
  }
}

1;
