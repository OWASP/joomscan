#start find backup
$btf=0;
dprint("Finding common backup files name");
@backups = ('backup.zip','upload.zip','joomla.zip','site.zip','joomla.tar','joomla.tar.gz','site.tar.gz','2.zip','1.zip','database.zip','sql.zip','backup.sql','database.sql','Joomla.tar.gz','Joomla.zip','Joomla.tar','joom.zip');
foreach $back(@backups){
    if (($content_type, $doc_length, $mod_time, $expires, $server) =head("$target/$back")){
        if($content_type !~ m/text\/html/i){
            tprint("Backup file is found \nPath : $target/$back\n");
           $btf=1;
        }
    }
}
if($btf==0){
    fprint("Backup files are not found");
}
#end find backup
