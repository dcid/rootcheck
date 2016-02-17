# Rootcheck

Rootcheck is an open source command line tool that looks for indicators of compromise
on Linux or BSD systems. It tries to find known backdoors, kernel-level rootkits, malware
and insecure configuration settings.

It is included as part of OSSEC, but can also be executed separately from here as needed. 
If you suspect your server has been compromised it will certainly help with your investigation.


## Installation 
The installation is pretty simple. Just follow these 4 steps to get it started:


1- Download Rootcheck:
   # wget http://dcid.me/ossec-packages/rootcheck-latest.tar.gz

2- Install gcc and make. It comes by default on all BSD's and can be
   easily installed by running "apt-get install gcc make" on Debian/Ubuntu
   or "yum install gcc make" on CentOS/RedHat.

3- Run the install script:
   # cd *rootcheck*
   # ./install.sh

4- After the compilation is completed, you are ready to start using rootcheck:

   # ./rootcheck


Enjoy!



#EOF

