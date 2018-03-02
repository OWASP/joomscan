#start path disclosure

@plinks = ("mambo/mambots/editors/mostlyce/jscripts/tiny_mce/plugins/spellchecker/classes/PSpellShell.php","components/com_docman/dl2.php?archive=0&file=","libraries/joomla/utilities/compat/php50x.php","libraries/joomla/client/ldap.php","libraries/joomla/html/html/content.php","libraries/phpmailer/language/phpmailer.lang-joomla.php","libraries/phpxmlrpc/xmlrpcs.php","libraries/joomla/utilities/compat/php50x.php","index.php?option=com_jotloader&section[]=","index.php?option=com_jotloader&section[]=",'plugins/content/clicktocall/clicktocall.php','/index.php?option=com_remository&Itemid=53&func=[]select&id=5');
foreach $plink(@plinks){
    $source=$ua->get("$target/$plink")->decoded_content;
    if($source =~ m/Cannot modify header information/i || $source =~ m/trim()/i || $source =~ m/header already sent/i || $source =~ m/Fatal error/i || $source =~ m/errno/i || $source =~ m/Warning: /i){
        $pathdis="";
        $source =~ /array given in (.*?) on line/;
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
        goto pend;
    }
}
pend:;

#end path disclosure