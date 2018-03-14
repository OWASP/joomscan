package JoomScan::Logging;
use warnings;
use strict;

my  (@dlog, @tflog, $log);
$log = "";

sub dprint{
  my ($in) = @_;
  $in =~ s/\/\//\//g;
  $in =~ s/http:\//http:\/\//g;
  $in =~ s/https:\//https:\/\//g;
  $#dlog++;
  $dlog[$#dlog]=$in;
  $in="\n[+] $in\n";
  $log .= $in;
  print color("blue");
  print "$in";
}
sub tprint{
  my ($in) = @_;
  $in =~ s/\/\//\//g;
  $in =~ s/http:\//http:\/\//g;
  $in =~ s/https:\//https:\/\//g;
  $#tflog++;
  $tflog[$#tflog]=$in;
  $in="[++] $in\n";
  $log .= $in;
  print color("yellow");
  print "$in";
  print color("blue");
}
sub fprint{
  my ($in) = @_;
  $in =~ s/\/\//\//g;
  $in =~ s/http:\//http:\/\//g;
  $in =~ s/https:\//https:\/\//g;
  $#tflog++;
  $tflog[$#tflog]="1337false$in";
  $in="[++] $in\n";
  $log .= $in;
  print color("red");
  print "$in";
  print color("blue");
}
