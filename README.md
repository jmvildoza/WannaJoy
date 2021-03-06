# WannaJoy
Tool to regenerate WannaCry's AES-128-CBC keys in Windows XP SP2 and earlier

This tool is based on "Cryptanalysis of the Random Number Generator of the Windows
Operating System", a white paper authored by Leo Dorrendorf, Zvi Gutterman and Benny Pinkas.
Source: https://eprint.iacr.org/2007/419.pdf



### Overview

WannaCry uses its own implementation of AES-128-CBC to encrypt files, however this function invokes CryptGenRandom() to generate one AES-128bit key *per file* before each key is encrypted by RSA-2048. According to the aforementioned white-paper, Windows 2000 and Windows XP PRNG's are flawed because of two main reasons:

1. It uses RC4 to encrypt entropy, which can be run backwards to compute previous PRNG's states once the current PRNG's states are known.
2. Although the PRNG uses a robust combination of diverse entropy sources, it is only refreshed every 16KB (16384 bits) of random data output, thus enabling us to regenerate up to 1024 keys.

These tools use a Windows PRNG simulator that has been written from scratch, which can be used to compute earlier outputs of the original CryptGenRandom(). Therefore, we can apply the following procedures:

1. Generate the latest CryptGenRandom() outputs and build 1024 AES-128keys.
2. Encrypt each AES key with WannaCry's public key (for comparison).
3. Iterate through affected files and read their RSA-2048 encrypted AES-128 keys, then proceed to decrypt the file content if they match. This can be accomplished using *wanafork* https://github.com/odzhan/wanafork

### NOTES:
* This *might* work even after WCRY.EXE has been closed or PC has been restarted.
* Only the latest 1024 files can be recovered at most, provided the CryptGenRandom() hadn't been after WCRY attacked.
* In rare occasions, it might be possible to recover RSA keys derived from the PRNG, but very few files must have been encrypted so that the 16KB limit remains unexceeded.
* The original tools source code can only be compiled using Windows SDK. 

* The current source code has been modified to run in Visual Studio C++ 6.0.

## TO DO LIST

### Get proper addresses of current PRNG's states, which vary across different version builds of Windows

I only managed to get it to run in Windows 2000: 
Windows 2000 Service Pack 4 (with the following DLL and driver versions:
ADVAPI32.DLL 5.0.2195.6876, RSAENH.DLL 5.0.2195.6611 and KSECDD.SYS 5.0.2195.824)

In order to support other OS versions, the addresses that point to the respective PRNG's states must be added.


