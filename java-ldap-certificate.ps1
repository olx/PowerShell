<#
    .Synopsis
        Скрипт автоматизирует процесс доставки/обновления сертификта в java хранилище     
        .Parameter ldapip 
            Определяет LDAP Server
        .Parameter port
            Определяет SSL PORT 
        .Parameter keystore
            Опеределят путь к хранилищу сертификатов      
        .Parameter password
            Опеределят пароль от хранилища сертификатов                  
    .Notes
		Copyright © 2018 Oleg Gassak aka Ledzhy   
#>
param (
    [string]$ldapip = "192.168.1.1",
    [int]$port = 3269,
    [string]$keystore = "C:\tmp\cacerts",
    [string]$password = "changeit"
)

$ldapCert = $null
[System.Net.IPAddress]$IP = [System.Net.IPAddress]::Parse($ldapip)
$TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient

try {
    
    $TcpClient.Connect($IP, $port)
    $TcpStream = $TcpClient.GetStream()

    $Callback = { 
        param (
            $sender, 
            $cert, 
            $chain, 
            $errors
            ) 
        return $true 
    }

    $SslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($TcpStream, $true, $Callback)
    try {

        $SslStream.AuthenticateAsClient('')
        $ldapCert = $SslStream.RemoteCertificate

    } finally {
        $SslStream.Dispose()
    }
} 
finally {
    $TcpClient.Dispose()
}

if (!$ldapCert) {
    break
}

if ($ldapCert) {
    if ($ldapCert -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        $ldapCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $ldapCert
    }
}
$alias = ($ldapCert.GetName()).Split("=")[1]
$keytool = Get-ChildItem -Path "C:\Program Files\Java\" -Include keytool.exe -File -Recurse -ErrorAction SilentlyContinue

if (!$keytool) {
    break
}

function Run-Keytool() {
    param (
        [string]$keytool = $null,
        [string]$cmd = $null
    )
    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = $keytool
    $ps.StartInfo.Arguments = $cmd
    $ps.StartInfo.RedirectStandardOutput = $True
    $ps.StartInfo.UseShellExecute = $false
    $ps.start() | Out-Null
    $ps.WaitForExit()
    $out = $ps.StandardOutput.ReadToEnd()    
    return $out
}

function Import-CertificateToJavaStore() {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate = $null,
        [string]$alias = $null,
        [string]$keystore = $null,
        [string]$password = $null    
    )
    $bytes = $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $file = "$($env:TEMP)\$($alias).cer" 
    [System.IO.File]::WriteAllBytes( $file, $bytes )
    #$file.Refresh()   
    $cmd = ' -import -noprompt -alias {0} -file "{1}" -keystore "{2}" -storepass {3}' -f $alias, $file, $keystore, $password
    $out = Run-Keytool -keytool $keytool -cmd $cmd
    return $out
}

$cmd = ' -list -rfc -keystore "{0}" -alias {1} -storepass {2}' -f $keystore, $alias, $password

$out = Run-Keytool -keytool $keytool.FullName -cmd $cmd

if ($out -match ("Alias <{0}> does not exist" -f $alias)) {
    $res = Import-CertificateToJavaStore -certificate $ldapCert -alias $alias -keystore $keystore -password $password | Out-Null
}
else {
    <#
        формируем объект для удобства работы
    #>
    $regex = "(?<=-----BEGIN CERTIFICATE-----)(.*)(?=-----END CERTIFICATE-----)"
    $data = [regex]::Match($out,$regex,[System.Text.RegularExpressions.RegexOptions]::Singleline)    
    $enc = [system.Text.Encoding]::UTF8
    $data = $enc.GetBytes($data) 
    $storeCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $storeCert.Import($data)

    if ($storeCert.GetExpirationDateString() -ne $ldapCert.GetExpirationDateString()) {
        $res = Import-CertificateToJavaStore -certificate $ldapCert -alias $alias -keystore $keystore -password $password | Out-Null
    }
}

