murphy@backbox:~/github/joomscan/core$ perl -c update.pl 
syntax error at update.pl line 7, near "our "
Global symbol "@EXPORT_OK" requires explicit package name at update.pl line 7.
Can't use global @_ in "my" at update.pl line 10, near "= @_"
Global symbol "$ua" requires explicit package name at update.pl line 11.
syntax error at update.pl line 23, near "}"
update.pl had compilation errors.
murphy@backbox:~/github/joomscan/core$ perl -c update.pl 
update.pl syntax OK
murphy@backbox:~/github/joomscan/core$ git rm update.pl
error: the following file has local modifications:
    core/update.pl
(use --cached to keep the file, or -f to force removal)
murphy@backbox:~/github/joomscan/core$ git rm -f  update.pl
rm 'core/update.pl'
murphy@backbox:~/github/joomscan/core$ ls
report.pl
murphy@backbox:~/github/joomscan/core$ git rm report.pl
rm 'core/report.pl'
murphy@backbox:~/github/joomscan/core$ 