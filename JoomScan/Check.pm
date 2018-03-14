package JoomScan::Check;
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
  $response=$ua->get("$target/robots.txt");
  my $headers  = $response->headers();
  my $content_type =$headers->content_type();
  if ($response->status_line =~ /200/g and
      $content_type =~ /text\/plain/g) {
    my $source = $response->decoded_content;
    my @lines = split /\n/, $source;
    my $probot="";
    foreach my $line( @lines ) {
      if($line =~ /llow:/g){
        $between=substr($line, index($line, ': ')+2, 99999);
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
  @plinks = ("mambo/mambots/editors/mostlyce/jscripts/tiny_mce/plugins/spellchecker/classes/PSpellShell.php","components/com_docman/dl2.php?archive=0&file=","libraries/joomla/utilities/compat/php50x.php","libraries/joomla/client/ldap.php","libraries/joomla/html/html/content.php","libraries/phpmailer/language/phpmailer.lang-joomla.php","libraries/phpxmlrpc/xmlrpcs.php","libraries/joomla/utilities/compat/php50x.php","index.php?option=com_jotloader&section[]=","index.php?option=com_jotloader&section[]=",'plugins/content/clicktocall/clicktocall.php','/index.php?option=com_remository&Itemid=53&func=[]select&id=5');
  foreach $plink(@plinks){
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
  @configs = ('server-status','server-info');
  foreach my $config(@configs){
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
  foreach $er(@error){
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

1;

#end admin finder
