![Version 0.0.6](https://img.shields.io/badge/Version-0.0.6-green.svg)
![perl](https://img.shields.io/badge/Perl-5.x-yellow.svg)
[![GPLv3 License](https://img.shields.io/badge/License-GPLv3-red.svg)](https://github.com/rezasp/joomscan/blob/master/LICENSE.md)
[![Twitter](https://img.shields.io/badge/Twitter-@OWASP_JoomScan-blue.svg)](http://twitter.com/OWASP_JoomScan)
[![Leader](https://img.shields.io/badge/Twitter-@rezesp-blue.svg)](http://www.twitter.com/rezesp)
[![Leader](https://img.shields.io/badge/Twitter-@Ali_Razmjo0-blue.svg)](http://www.twitter.com/Ali_Razmjo0)


<img src="https://raw.githubusercontent.com/rezasp/Trash/master/joomscan.png" width="200"><img src="https://raw.githubusercontent.com/rezasp/Trash/master/owasp.png" width="500">

======

OWASP JoomScan Project
======

OWASP JoomScan  (short for [Joom]la Vulnerability [Scan]ner) is an opensource project in perl programming language to detect Joomla CMS vulnerabilities and analysis them.

### WHY OWASP JOOMSCAN  ?

If you want to do a penetration test on a Joomla CMS, OWASP JoomScan is Your best shot ever!
This Project is being faster than ever and updated with the latest Joomla vulnerabilities.


# INSTALL

    git clone https://github.com/rezasp/joomscan.git
    cd joomscan
    perl joomscan.pl


# JOOMSCAN ARGUMENTS

    Usage:	joomscan.pl [options]

    --url | -u <URL>                |   The Joomla URL/domain to scan.
    --enumerate-components | -ec    |   Try to enumerate components.

    --cookie <String>               |   Set cookie.
    --user-agent | -a <user-agent>  |   Use the specified User-Agent.
    --random-agent | -r             |   Use a random User-Agent.
    --timeout <time-out>            |   set timeout.
    --about                         |   About Author
    --update                        |   Update to the latest version.
    --help | -h                     |   This help screen.
    --version                       |   Output the current version and exit.


# OWASP JOOMSCAN EXAMPLES

Do default checks...<br>
```perl joomscan.pl --url www.example.com```<br>
or<br>
```perl joomscan.pl -u www.example.com```
<br>
<br>
Enumerate installed components...<br>
```perl joomscan.pl --url www.example.com --enumerate-components```<br>
or<br>
```perl joomscan.pl -u www.example.com --ec```<br>
<br>

Set cookie<br>
```perl joomscan.pl --url www.example.com --cookie "test=demo;"```
<br><br>

Set user-agent<br>
```perl joomscan.pl --url www.example.com --user-agent "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"```<br>
or<br>
```perl joomscan.pl -u www.example.com -a "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"```<br>
<br><br>

Set random user-agent<br>
```perl joomscan.pl -u www.example.com --random-agent```<br>
or<br>
```perl joomscan.pl --url www.example.com -r```<br>
<br>

Update Joomscan...<br>
```perl joomscan.pl --update```<br><br>


# OWASP PAGE

[https://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project](https://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project)

# GIT REPOSITORY

[https://github.com/rezasp/joomscan](https://github.com/rezasp/joomscan)

# ISSUES

[https://github.com/rezasp/joomscan/issues](https://github.com/rezasp/joomscan/issues)

# PROJECT LEADERS

*  Mohammad Reza Espargham           [ reza[dot]espargham[at]owasp[dot]org ]
*  Ali Razmjoo                                    [ ali[dot]razmjoo[at]owasp[dot]org ]


<br><br>
OWASP JoomScan introduction (Youtube)

[![OWASP JoomScan introduction](https://img.youtube.com/vi/Ik2CJ9LkuoI/0.jpg)](https://www.youtube.com/watch?v=Ik2CJ9LkuoI)
