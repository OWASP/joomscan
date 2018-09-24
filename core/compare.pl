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