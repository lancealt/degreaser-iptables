degreaser-iptables
==================

degreaser-iptables is a set of modules for the Linux xtables architecture that can
detect and avoid network tarpits such as [LaBrea](http://labrea.sourceforge.net). 

The algorithm used is based the [degreaser](http://www.cmand.org/degreaser) tarpit
scanning tool.


Installation
------------
degreaser-iptables uses the [xtables-addons](http://xtables-addons.sourceforge.net) framework
and can be added using the **xa-download-more** script included in the xtables-addons disribution.

1. Download or clone the xtables-addons repository

    git clone git://git.code.sf.net/p/xtables-addons/xtables-addons

2. Add the following line to the 'sources' file:

    http://www.cmand.org/degreaser

3. Run the xa-download-more script to download and merge the degreaser-iptables code in to
   your local git repository.

4. Configure, compile, and install the xtables-addons package as follows:

    ./autogen.sh
    ./configure
    make
    make install


Configuration
-------------
degreaser-iptables contains two xtables modules useful in detecting and avoiding network
tarpits. The first module is the 'notarpit' match module. This module matches packets
(specifically SYN/ACKs) that are suspected tarpits. The 'RESET' target module simply
resets the *destination* end of a TCP packet it receives. Together, these two modules can
be used to detect and avoid network tarpits. For example:

    iptables -A INPUT -m notarpit -j RESET

In this rule, if the local machine tries to establish a TCP connection with a remote host,
and the remote host responds with a SYN/ACK that is consistent with a network tarpit, the
application on the local machine will have its connection reset, thus avoiding getting stuck
in the tarpit.


Testing
--------
Using the degreaser-iptables modules as described above can significantly improve the
performance of network scans that require transfer of some TCP data (such as banner grabbers).

In one test case, a /24 mostly filled with non-persistent mode LaBrea tarpits was scanned using
nmap with the following options:

    nmap -sV XXX.XXX.XXX.XXX/24 -p 80

A normal scan without using degreaser-iptables completed in 2103 seconds. When using the 
degreaser-iptables modules, the same scan completed in only 45 seconds.
