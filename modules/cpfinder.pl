#start admin finder
dprint("admin finder");

$amtf=0;
@admins = ('administrator','admin','panel','webadmin','modir','manage','administration','joomla/administrator','joomla/admin');
foreach $admin(@admins){
    $source=$ua->get("$target/$admin/");
    if($source->code=~200 or $source->code=~403 or $source->code=~500 or $source->code=~501){
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

#end admin finder