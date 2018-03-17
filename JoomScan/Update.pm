package JoomScan::Update;
use warnings;
use strict;
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(lookup_new_version);


sub lookup_new_version {
  my ($ua, $version) = @_;
  print "\n[+] Checking newest version\n";

  my $response = $ua->get('http://raw.githubusercontent.com/rezasp/joomscan/master/version');

  if($response->is_success){
    if($response->decoded_content !~ /$version/){
      print "\n[!] New version available on http://github.com/rezasp/joomscan \n\n";
    }else {
      print "\n[!] No new version available\n\n";

    }
  }else{
    print "\nNetwork error!\n";
  }
}

1;
