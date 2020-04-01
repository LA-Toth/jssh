JSSH - An SSH proxy written in Java
===================================

The code is written based on RFC 4250 to 4254 and the related RFCs.

I must note: As I saw so many logs from an SSH proxy, I reused
some of its log messages to see what happens without thinking
on the format of logs.

There are other open-source SSH implementation, including [OpenSSH], or
in Java like [JSCH] (for Java versions older than 1.5 (v5))

Purpose
-------

The purpose is practicing Java 13+ (or likely Java 8) and getting familiar
with the encryption.

The goal is to have a proxy supporting public key authentication
and of course password and keyboard-interactive auths, too. This could
open dozens of possibilities, but as a hobby project those parts are
not planned.


Structure
---------

Packages reflect the RFC layout - mostly.
The only exception is ``Config``, which is "global", others are in subpackages.

The packages:
* ``auth``: the package of RFC 4252 SSH Authentication Protocol
* ``connection``: the package of RFC 4254 SSH Connection Protocol
* ``kex``: the key exchange algorithms bases on RFC 4253 and others
* ``transportlayer``: the primary package for RFC 4253 SSH Transport Layer Protocol
* ``proxy``: the common codes and the main proxy Runnable (thread) implementation
* ``threading``: the thread management package, independent from SSH

The global ``JSsh`` class accepts the connections and starts threads.

[JSCH]: https://sourceforge.net/projects/jsch/
[OpenSSH]: https://www.openssh.com
