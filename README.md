# FortiCrack

Decrypt encrypted Fortinet FortiOS firmware images

_Developed by Bishop Fox Team X_

![demo animation](demo.gif)

## Requirements

This tool is intended to run in a Linux environment.

Install `python3` and `gzip` packages for your system.

## Usage

Download an encrypted firmware image from the Fortinet support site, then run this tool against it.

```
❯ ./forticrack.py -h
Usage: python3 forticrack.py <FILENAME>
```

FortiCrack uses a known-plaintext attack to derive the file encryption key, then decrypts the image data. More details can be found on our blog: [Breaking Fortinet Firmware Encryption](https://bishopfox.com/blog/breaking-fortinet-firmware-encryption)

## Example

```
❯ ./forticrack.py FGT_100D-v6-build9451-FORTINET.out
 ___  __   __  ___    __   __        __       
|__  /  \ |__)  |  | /  ` |__)  /\  /  ` |__/ 
|    \__/ |  \  |  | \__, |  \ /~~\ \__, |  \ 

[+] Decrypting FGT_100D-v6-build9451-FORTINET.out
[+] Loaded image data
[+] Found key: oAbBIcDde7FfgGHhiIjJ7KlLmsnN3OPP
[+] Validated: FG100D-6.04-FW-build1966-23031
[+] Decrypted: FGT_100D-v6-build9451-FORTINET.decrypted
```

## Limitations

All encrypted Fortinet firmware images use the same weak encryption scheme (at the time of this writing), but not all of them have the same known plaintext. This attack will work against the majority of images, but certain products will require you to modify the exploit in order to derive the key successfully.

## License

This project is licensed under [GPL v3](LICENSE).
