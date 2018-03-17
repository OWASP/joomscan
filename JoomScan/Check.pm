package JoomScan::Check;
use warnings;
use strict;
use Exporter;
use LWP::Simple;
use JoomScan::Logging qw(dprint tprint fprint);

our @ISA = qw(Exporter);
our @EXPORT_OK = qw(check_reg check_robots_txt check_path_disclosure
		    check_misconfiguration check_error_logs
		    check_dirlisting check_debug_mode
		    check_admin_pages check_backups check_configs
		    detect_joomla_version);

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
    foreach my $line ( @lines ) {
      if ($line =~ /llow:/g) {
        my $between=substr($line, index($line, ': ')+2, 99999);
        $probot.="$target$between\n";
      }
    }
    tprint("robots.txt is found\npath : $target/robots.txt \n\nInteresting path found from robots.txt\n$probot");
  } else {
    fprint("robots.txt is not found");
  }
}

#start path disclosure

sub check_path_disclosure {
  my ($ua, $target) = @_;
  my @plinks = ("components/com_docman/dl2.php?archive=0&file=",
		"index.php?option=com_jotloader&section[]=",
		"index.php?option=com_jotloader&section[]=",
		"libraries/joomla/client/ldap.php",
		"libraries/joomla/html/html/content.php",
		"libraries/joomla/utilities/compat/php50x.php",
		"libraries/joomla/utilities/compat/php50x.php",
		"libraries/phpmailer/language/phpmailer.lang-joomla.php",
		"libraries/phpxmlrpc/xmlrpcs.php",
		"mambo/mambots/editors/mostlyce/jscripts/tiny_mce/plugins/spellchecker/classes/PSpellShell.php",
		'/index.php?option=com_remository&Itemid=53&func=[]select&id=5',
		'plugins/content/clicktocall/clicktocall.php');
  foreach my $plink (@plinks) {
    my $source=$ua->get("$target/$plink")->decoded_content;
    if ($source =~ m/Cannot modify header information/i or
	$source =~ m/trim()/i or
	$source =~ m/header already sent/i or
	$source =~ m/Fatal error/i or
	$source =~ m/errno/i or
	$source =~ m/Warning: /i) {
      my $pathdis="";
      my $source =~ /array given in (.*?) on line/;
      $pathdis=$1;
      if ($pathdis !~ "") {
        $source =~ /array given in (.*?) on line /;
        $pathdis=$1;
      }
      if ($pathdis !~ "") {
        $source =~ /occurred in (.*?) in line /;
        $pathdis=$1;
      }
      if ($pathdis !~ "") {
        $source =~ /occurred in (.*?) on line/;
        $pathdis=$1;
      }
      if ($pathdis !~ "") {
        $source =~ /on a non-object in (.*?) on line/;
        $pathdis=$1;
      }
      if ($pathdis !~ "") {
        $source =~ /on a non-object in (.*?) in line/;
        $pathdis=$1;
      }
      if ($pathdis !~ "") {
        $source =~ /No such file or directory (errno 2) in (.*?) on line/;
        $pathdis=$1;
      }
      if ($pathdis !~ "") {
        $source =~ /No such file or directory in (.*?) in line/;
        $pathdis=$1;
      }
      if ($pathdis !~ "") {
        $source =~ /not found in (.*?) in line/;
        $pathdis=$1;
      }
      if ($pathdis !~ "") {
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

sub check_misconfiguration {
  my ($ua, $target) = @_;
  my $ctf=0;
  dprint("Checking apache info/status files");
  my @configs = ('server-status','server-info');
  foreach my $config (@configs) {
    my $source = $ua->get("$target/$config")->decoded_content;
    if ($source =~ m/Apache Server Information/i or
	$source =~ m/Server Root/i or
	$source =~ m/Apache Status/i) {
      tprint("Interesting file is found \n$target/$config");
      $ctf=1;
    }
  }
  if ($ctf==0) {
    fprint("Readable info/status files are not found");
  }
}

sub check_error_logs {
  my ($ua, $target) = @_;
  dprint("Finding common log files name");
  my $ertf=0;
  my @error = ('error.log','error_log','php-scripts.log',
	       'php.errors','php5-fpm.log','php_errors.log','debug.log');
  foreach my $er (@error) {
    if (my ($content_type, $doc_length, $mod_time, $expires, $server) = head("$target/$er")) {
      if ($content_type !~ m/text\/html/i) {
        tprint("$er path :  $target/$er\n");
        $ertf=1;
      }
    }
  }
  if ($ertf==0) {
    fprint("error log is not found");
  }
}


sub check_dirlisting{
  my ($ua, $target) = @_;
  my $ctf=0;
  my @dirl = ('administrator/components',
	      'administrator/modules',
	      'administrator/templates',
	      'cache',
	      'components',
	      'images',
	      'images/banners',
	      'images/stories',
	      'includes',
	      'language',
	      'media',
	      'modules',
	      'templates',
	      'templates',
	      'tmp');
  my $cnftmp="";
  foreach my $dir (@dirl) {
    my $source = $ua->get("$target/$dir/")->decoded_content;
    if ($source =~ /<title>Index of/g or $source =~ /Last modified<\/a>/g) {
      $cnftmp="$cnftmp$target/$dir\n";
      $ctf=1;
    }
  }
  if ($ctf==1) {
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
  my @admins = ('administrator',
		'admin',
		'panel',
		'webadmin',
		'modir',
		'manage',
		'administration',
		'joomla/administrator',
		'joomla/admin');
  foreach my $admin (@admins) {
    my $source = $ua->get("$target/$admin/");
    if ($source->code=~/200/ or
	$source->code=~/403/ or
	$source->code=~/500/ or
	$source->code=~/501/) {
      $amtf=1;
      $adming=$admin;
      last;
    }
  }
  if ($amtf==1) {
    tprint("Admin page : $target/$adming/");
  } else {
    fprint("Admin page not found");
  }
  return ($amtf, $adming);
}

sub check_backups {
  my ($ua,
      $target) = @_;
  my $btf=0;
  dprint("Finding common backup files name");
  my @backups = ('1.gz',
		 '1.rar',
		 '1.save',
		 '1.tar',
		 '1.tar.bz2',
		 '1.tar.gz',
		 '1.tgz',
		 '1.tmp',
		 '1.txt',
		 '1.zip',
		 '2.back',
		 '2.backup',
		 '2.gz',
		 '2.rar',
		 '2.save',
		 '2.tar',
		 '2.tar.bz2',
		 '2.tar.gz',
		 '2.tgz',
		 '2.tmp',
		 '2.txt',
		 '2.zip',
		 'Joomla.back',
		 'Joomla.backup',
		 'Joomla.bak',
		 'Joomla.bck',
		 'Joomla.bkp',
		 'Joomla.copy',
		 'Joomla.gz',
		 'Joomla.old',
		 'Joomla.orig',
		 'Joomla.rar',
		 'Joomla.sav',
		 'Joomla.save',
		 'Joomla.tar',
		 'Joomla.tar.bz2',
		 'Joomla.tar.gz',
		 'Joomla.tgz',
		 'Joomla.zip',
		 'backup.back',
		 'backup.backup',
		 'backup.bak',
		 'backup.bck',
		 'backup.bkp',
		 'backup.copy',
		 'backup.gz',
		 'backup.old',
		 'backup.orig',
		 'backup.rar',
		 'backup.sav',
		 'backup.save',
		 'backup.sql.back',
		 'backup.sql.backup',
		 'backup.sql.bak',
		 'backup.sql.bck',
		 'backup.sql.bkp',
		 'backup.sql.copy',
		 'backup.sql.gz',
		 'backup.sql.old',
		 'backup.sql.orig',
		 'backup.sql.rar',
		 'backup.sql.sav',
		 'backup.sql.save',
		 'backup.sql.tar',
		 'backup.sql.tar.bz2',
		 'backup.sql.tar.gz',
		 'backup.sql.tgz',
		 'backup.sql.tmp',
		 'backup.sql.txt',
		 'backup.sql.zip',
		 'backup.sql~',
		 'backup.tar',
		 'backup.tar.bz2',
		 'backup.tar.gz',
		 'backup.tgz',
		 'backup.txt',
		 'backup.zip',
		 'database.back',
		 'database.backup',
		 'database.bak',
		 'database.bck',
		 'database.bkp',
		 'database.copy',
		 'database.gz',
		 'database.old',
		 'database.orig',
		 'database.rar',
		 'database.sav',
		 'database.save',
		 'database.sql.back',
		 'database.sql.backup',
		 'database.sql.bak',
		 'database.sql.bck',
		 'database.sql.bkp',
		 'database.sql.copy',
		 'database.sql.gz',
		 'database.sql.old',
		 'database.sql.orig',
		 'database.sql.rar',
		 'database.sql.sav',
		 'database.sql.save',
		 'database.sql.tar',
		 'database.sql.tar.bz2',
		 'database.sql.tar.gz',
		 'database.sql.tgz',
		 'database.sql.tmp',
		 'database.sql.txt',
		 'database.sql.zip',
		 'database.sql~',
		 'database.tar',
		 'database.tar.bz2',
		 'database.tar.gz',
		 'database.tgz',
		 'database.tmp',
		 'database.txt',
		 'database.zip',
		 'joom.back',
		 'joom.backup',
		 'joom.bak',
		 'joom.bck',
		 'joom.bkp',
		 'joom.copy',
		 'joom.gz',
		 'joom.old',
		 'joom.orig',
		 'joom.rar',
		 'joom.sav',
		 'joom.save',
		 'joom.tar',
		 'joom.tar.bz2',
		 'joom.tar.gz',
		 'joom.tgz',
		 'joom.zip',
		 'joomla.back',
		 'joomla.backup',
		 'joomla.bak',
		 'joomla.bck',
		 'joomla.bkp',
		 'joomla.copy',
		 'joomla.gz',
		 'joomla.old',
		 'joomla.orig',
		 'joomla.rar',
		 'joomla.sav',
		 'joomla.save',
		 'joomla.tar',
		 'joomla.tar.bz2',
		 'joomla.tar.gz',
		 'joomla.tgz',
		 'joomla.zip',
		 'site.back',
		 'site.backup',
		 'site.bak',
		 'site.bck',
		 'site.bkp',
		 'site.copy',
		 'site.gz',
		 'site.old',
		 'site.orig',
		 'site.rar',
		 'site.sav',
		 'site.save',
		 'site.tar',
		 'site.tar.bz2',
		 'site.tar.gz',
		 'site.tgz',
		 'site.zip',
		 'sql.zip.back',
		 'sql.zip.backup',
		 'sql.zip.bak',
		 'sql.zip.bck',
		 'sql.zip.bkp',
		 'sql.zip.copy',
		 'sql.zip.gz',
		 'sql.zip.old',
		 'sql.zip.orig',
		 'sql.zip.save',
		 'sql.zip.tar',
		 'sql.zip.tar.bz2',
		 'sql.zip.tar.gz',
		 'sql.zip.tgz',
		 'upload.back',
		 'upload.backup',
		 'upload.bak',
		 'upload.bck',
		 'upload.bkp',
		 'upload.copy',
		 'upload.gz',
		 'upload.old',
		 'upload.orig',
		 'upload.rar',
		 'upload.sav',
		 'upload.save',
		 'upload.tar',
		 'upload.tar.bz2',
		 'upload.tar.gz',
		 'upload.tgz',
		 'upload.zip');
  foreach my $back (@backups) {
    if (my ($content_type, $doc_length, $mod_time, $expires, $server) =head("$target/$back")) {
      if ($content_type !~ m/text\/html/i) {
        tprint("Backup file is found \nPath : $target/$back\n");
        $btf=1;
      }
    }
  }
  if ($btf==0) {
    fprint("Backup files are not found");
  }
}

sub check_configs{
  my ($ua, $target) = @_;
  #start config.php.x check

  my $ctf=0;
  dprint("Checking sensitive config.php.x file");
  my @configs = ('configuration.php~',
		 'configuration.php.new',
		 'configuration.php.new~',
		 'configuration.php.old',
		 'configuration.php.old~',
		 'configuration.bak',
		 'configuration.php.bak',
		 'configuration.php.bkp',
		 'configuration.txt',
		 'configuration.php.txt',
		 'configuration - Copy.php',
		 'configuration.php.swo',
		 'configuration.php_bak',
		 'configuration.php#',
		 'configuration.orig',
		 'configuration.php.save',
		 'configuration.php.original',
		 'configuration.php.swp',
		 'configuration.save',
		 '.configuration.php.swp',
		 'configuration.php1',
		 'configuration.php2',
		 'configuration.php3',
		 'configuration.php4',
		 'configuration.php4',
		 'configuration.php6',
		 'configuration.php7',
		 'configuration.phtml',
		 'configuration.php-dist');

  my $cnftmp="";
  foreach my $config (@configs) {
    my $source = $ua->get("$target/$config")->decoded_content;
    if ($source =~ m/public \$ftp_pass/i or
	$source =~ m/\$dbtype/i or
	$source =~ m/force_ssl/i or
	$source =~ m/mosConfig_secret/i or
	$source =~ m/mosConfig_dbprefix/i ) {
      $cnftmp = "$cnftmp Readable config file is found \n config file path: ".
	         "$target/$config\n";
      $ctf=1;
    }
  }
  if ($ctf==0) {
    fprint("Readable config files are not found");
  } else {
    tprint($cnftmp);
  }
}

sub detect_joomla_version {
  my ($ua, $target, $timeout) = @_;
  dprint("Detecting Joomla Version");
  $ua->timeout(10);
  my $ver;
  my $response = $ua->get("$target");
  if (!$response->is_success) {
    print color("red");
    print "[++] The target is not alive!\n\n";
    print color("reset");
    exit 0;
  }
  $ua->timeout($timeout);

  my $source = $ua->get("$target/")->as_string;
  if($source =~ /X-Meta-Generator\:(.*?)\n/){
    my $ppp = $1;
    if($ppp =~ /[0-9]+(\.[0-9]+)+/g){
      $ver="Joomla $&";
    }
  }

  if($ver !~ m/\./i){
    my @vers = ('administrator/manifests/files/joomla.xml',
                'language/en-GB/en-GB.xml',
                'administrator/components/com_content/content.xml',
                'administrator/components/com_plugins/plugins.xml',
                'administrator/components/com_media/media.xml',
                'mambots/content/moscode.xml');
    foreach my $verc(@vers){
      $source=$ua->get("$target/$verc")->decoded_content;
      if($source =~ /\<version\>(.*?)\<\/version\>/){
        $ver="Joomla $1";
        last;
      }
    }
  }
  if($ver !~ m/\./i){
    my @vers = ('language/en-GB/en-GB.xml',
                'templates/system/css/system.css',
                'media/system/js/mootools-more.js',
                'language/en-GB/en-GB.ini',
                'htaccess.txt',
                'language/en-GB/en-GB.com_media.ini');
    foreach my $verc(@vers){
      $source=$ua->get("$target/$verc")->decoded_content;
      if($source =~ /system\.css 20196 2011\-01\-09 02\:40\:25Z ian/ or
         $source =~ /MooTools\.More\=\{version\:\"1\.3\.0\.1\"/ or
         $source =~ /en-GB\.ini 20196 2011\-01\-09 02\:40\:25Z ian/ or
         $source =~ /en-GB\.ini 20990 2011\-03\-18 16\:42\:30Z infograf768/ or
         $source =~ /20196 2011\-01\-09 02\:40\:25Z ian/){
        $ver="Joomla 1.6";
        last;
      }elsif($source =~ /system\.css 21322 2011\-05\-11 01\:10\:29Z dextercowley / or
             $source =~ /MooTools\.More\=\{version\:\"1\.3\.2\.1\"/ or
             $source =~ /22183 2011\-09\-30 09\:04\:32Z infograf768/ or
             $source =~ /21660 2011\-06\-23 13\:25\:32Z infograf768/){
        $ver="Joomla 1.7";
        last;
      }elsif($source =~ /Joomla! 1.5/ or
             $source =~ /MooTools\=\{version\:\'1\.12\'\}/ or
             $source =~ /11391 2009\-01\-04 13\:35\:50Z ian/){
        $ver="Joomla 1.5";
        last;
      }elsif($source =~ /Copyright \(C\) 2005 \- 2012 Open Source Matters/ or
             $source =~ /MooTools.More\=\{version\:\"1\.4\.0\.1\"/){
        $ver="Joomla 2.5";
        last;
      }elsif($source =~ /<meta name=\"Keywords\" content=\"(.*?)\">\s+<meta name/){
        $ver="Joomla $1";
        last;
      }elsif($source =~ /(Copyright \(C\) 2005 - 200(6|7))/ or
             $source =~ /47 2005\-09\-15 02\:55\:27Z rhuk/ or
             $source =~ /423 2005\-10\-09 18\:23\:50Z stingrey/ or
             $source =~ /1005 2005\-11\-13 17\:33\:59Z stingrey/ or
             $source =~ /1570 2005\-12\-29 05\:53\:33Z eddieajau/ or
             $source =~ /2368 2006\-02\-14 17\:40\:02Z stingrey/ or
             $source =~ /1570 2005\-12\-29 05\:53\:33Z eddieajau/ or
             $source =~ /4085 2006\-06\-21 16\:03\:54Z stingrey/ or
             $source =~ /4756 2006\-08\-25 16\:07\:11Z stingrey/ or
             $source =~ /5973 2006\-12\-11 01\:26\:33Z robs/ or
             $source =~ /5975 2006\-12\-11 01\:26\:33Z robs/){
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

  if($ver !~ m/\./i){
    fprint("ver 404\n")
  }
  else{
    tprint("$ver");
  }
  return $ver;
}


1;
