#start Checking common logs
dprint("Finding common log files name");
$ertf=0;
@error = ('error.log','error_log','php-scripts.log','php.errors','php5-fpm.log','php_errors.log','debug.log','security.txt','.well-known/security.txt');
foreach $er(@error){
    if (($content_type, $doc_length, $mod_time, $expires, $server) =head("$target/$er")){
        if($content_type !~ m/text\/html/i){
            tprint("$er path :  $target/$er\n");
           $ertf=1;
        }
    }
}
if($ertf==0) {
    fprint("error log is not found");
}
#end Checking common logs