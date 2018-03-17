package JoomScan::VulnDB;
use warnings;
use strict;
use Exporter;
use Logging qw(fprint);
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(check_components);


sub max {
  my $x = shift;
  my $y = shift;
  return ( $x > $y ? $x : $y );
}

sub version_compare {
  my $ver1 = shift || 0;
  my $ver2 = shift || 0;
  my @v1 = split /[.+:~-]/, $ver1;
  my @v2 = split /[.+:~-]/, $ver2;
  for ( my $i = 0 ; $i < max( scalar(@v1), scalar(@v2) ) ; $i++ ) {
    # Add missing version parts if one string is shorter than the other
    # i.e. 0 should be lt 0.2.1 and not equal, so we append .0
    # -> 0.0.0 <=> 0.2.1 -> -1
    push( @v1, 0 ) unless defined( $v1[$i] );
    push( @v2, 0 ) unless defined( $v2[$i] );
    if ( int( $v1[$i] ) > int( $v2[$i] ) ) {
      return 1;
    }
    elsif ( int( $v1[$i] ) < int( $v2[$i] ) ) {
      return -1;
    }
  }
  return 0;
}

sub check_components {
  my ($ua, $target, $amtf, $adming) = @_;
  #start find components
  my $btf=0;
  my @ffiles = ('WS_FTP.LOG',
		'README.txt',
		'readme.txt',
		'README.md',
		'readme.md',
		'LICENSE.TXT',
		'license.txt',
		'LICENSE.txt',
		'licence.txt',
		'CHANGELOG.txt',
		'changelog.txt',
		'MANIFEST.xml',
		'manifest.xml',
		'error_log',
		'error.log');

  $ua->requests_redirectable(undef);

  open(my $DB,"exploit/db/componentslist.txt");
  while( my $row = <$DB>)  {
    chomp $row;

    my $tmp="";
    my $response = $ua->get("$target/components/$row/");
    my $headers  = $response->headers();
    my $content_type =$headers->content_type();
    if ($response->status_line =~ /200/g ) {
      $tmp.="Name: $row\nLocation : $target/components/$row/\n";
      my $source=$response->decoded_content;
      if ($source =~ /<title>Index of/g or
	  $source =~ /Last modified<\/a>/g) {
	$tmp.="Directory listing is enabled : $target/components/$row/\n";
      }
      $btf=1;

      #components/com_
      foreach my $ffile(@ffiles){
	$response=$ua->get("$target/components/$row/$ffile");
	my $headers  = $response->headers();
	my $content_type =$headers->content_type();
	if ($response->status_line =~ /200/g ) {
	  chomp $ffile;
	  $tmp.="$ffile : $target/components/$row/$ffile\n";
	}
      }
		#Version finder
      my $xm=$row;
      $xm=~ s/com_//g;

      $response=$ua->get("$target/components/$row/$xm.xml");
      my $headers  = $response->headers();
      my $sourcer=$response->decoded_content;
      if ($response->status_line =~ /200/g ) {
	$sourcer =~ /type=\"component\" version=\"(.*?)\"/;
	my $comversion = $1;
	$tmp.="Installed version : $comversion\n";

				}

      open(my $FB,"exploit/db/comvul.txt");
      while( my $row = <$FB>)  {
	my @matches;
	while ($row =~/\[(.*?)\]/g) {
	  push @matches, $1;
	}

	if ( $matches[1] eq $xm) {
	  #compare install version vs fixed version
	  if(my $comversion =~ /\./ and $matches[6] =~ /\./){
	    $tmp.="$comversion\n";
	    $a=$comversion;
	    $b=$matches[6];
	    if(!&version_compare("$a","$b") == 1) {

	      $tmp.= "[!] We found vulnerable component\n";
	    }else{
	      $tmp.="[!] We found the component \"com_$xm\", but since the component version was not available we cannot ensure that it's vulnerable, please test it yourself.\n";
	    }

	  }else{
	    $tmp.="[!] We found the component \"com_$xm\", but since the component version was not available we cannot ensure that it's vulnerable, please test it yourself.\n";
	  }

	  $tmp.= "Title : ". $matches[0] . "\n" if $matches[0] !~ /-/;
	  $tmp.=  "Exploit date : ". $matches[2]. "\n" if $matches[2] !~ /-/;
	  $tmp.=  "Reference : http://www.cvedetails.com/cve/CVE-". $matches[3]. "\n" if $matches[3] !~ /-/ and $matches[3] !~ /\,/;
	  if(index($matches[3], ',') != -1){
	    print 123;
	    my @pp=split(/\,/,$matches[3]);
	    my $tmtm="";
	    foreach my $tt(@pp){
	      $tmtm.= "Reference : http://www.cvedetails.com/cve/CVE-$tt\n";
	    }
	    $tmp.= $tmtm;
	  }
	  $tmp.=  "Reference : https:///www.exploit-db.com/exploits/". $matches[5]. "\n" if $matches[5] !~ /-/;
	  $tmp.=  "Component : ". $matches[4]. "\n" if $matches[4] !~ /-/;
	  $tmp.=  "Fixed in : ". $matches[6]. "\n" if $matches[6] !~ /-/;
	  #$tmp.=  "Introduced in : ". $matches[7]. "\n" if $matches[7] !~ /-/;
	}

      }
      close $FB;

      #admin/components/com_
      if($amtf==1){
	foreach my $ffile(@ffiles){
	  $response=$ua->get("$target/$adming/components/$row/$ffile");
	  my $headers  = $response->headers();
	  my $content_type =$headers->content_type();
	  if ($response->status_line =~ /200/g ) {
	    chomp $ffile;
	    $tmp.="$ffile : $target/$adming/components/$row/$ffile\n";
	  }
	}
      }
    }
    if($tmp){
      dprint("Enumeration component ($row)");
      tprint($tmp);
    }
  }
  if($btf==0){
    dprint("Enumeration component");
    fprint("components are not found");
  }
}


sub is_version_vulnerable{
  my($target, $version) = @_;
#start 
    dprint("Core Joomla Vulnerability");
    open(my $DB,"exploit/db/corevul.txt");
    my $vver=substr($version, index($version, ' ')+1, 6);
    $vver =~ s/ //g;
    while( my $row = <$DB>)  {
	chomp $row;
	my $fv=substr($row, 0, index($row, '|'));
	my $fd=substr($row, index($row, '|')+1, 1000);
	my @sbug = split /,/, $fv;
	foreach my $bs(@sbug){
	    if(($bs =~ m/$vver/i) && (substr($vver, 0, 1) eq substr($bs, 0, 1))){
		$fd =~ s/\$target/$target/g;
		$fd =~ s/\\n/\r\n/g;
		$fd =~ s/\|/\r\n\r\n/g;
		$vtmp.="$fd\n\n";
		$vvtf=1;
		last;
	    }
	}
    }
    if($vvtf==1){
	tprint("$vtmp");
    }else{
	fprint("Target Joomla core is not vulnerable");
    }
    close $DB;
}

1;
