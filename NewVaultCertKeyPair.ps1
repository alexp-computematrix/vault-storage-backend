$ErrorActionPreference = "Stop";


function ValidatePrincipalOrElevate {

    # Check if current principal is Administrator role
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent();
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentUser);
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);

    if (!$isAdmin) {

    # Restart and prompt for elevation
    $newProcess = (
        Start-Process `
        -FilePath "powershell.exe" `
        -ArgumentList "-File","$PSCommandPath" `
        -Verb RunAs `
        -PassThru
    );
    $newProcess.WaitForExit();
    exit $newProcess.ExitCode;
    }
}


function WritePEMEncodedCertKeyPair {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate
    )

    # ---- Create RSACng using private key from certificate ---- #
    $RSACng = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey(
        $certificate
    );

    # ---- Export private key blob ---- #
    $KeyBlob = $RSACng.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob);


    $exportDir = $(Get-Item $PSCommandPath).Directory.ToString();
    $certExportPath = $exportDir + "\cert.pem";
    $keyExportPath = $exportDir + "\key.pem";

    if ($certificate.FriendlyName -eq "VaultCACertificate") {
        $certExportPath = $exportDir + "\ca-cert.pem";
        $keyExportPath = $exportDir + "\ca-key.pem";
    };


    # ---- Build PEM encoded certificate ---- #
    (New-Object System.Text.StringBuilder).AppendLine(
            "-----BEGIN CERTIFICATE-----"
    ).AppendLine(
        [System.Convert]::ToBase64String(
            $certificate.RawData,
            [System.Base64FormattingOptions]::InsertLineBreaks
        )
    ).AppendLine(
            "-----END CERTIFICATE-----"
    ).ToString() | Out-File -FilePath $certExportPath -Encoding ascii;


    # ---- Build PEM encoded private key ---- #
        (New-Object System.Text.StringBuilder).AppendLine(
            "-----BEGIN PRIVATE KEY-----"
    ).AppendLine(
        [System.Convert]::ToBase64String(
            $KeyBlob,
            [System.Base64FormattingOptions]::InsertLineBreaks
        )
    ).AppendLine(
            "-----END PRIVATE KEY-----"
    ).ToString() | Out-File -FilePath $keyExportPath -Encoding ascii;

}


try {

    ValidatePrincipalOrElevate;

    # ---- Create Root CA certificate ---- #
    $VaultCACertificate = (
        New-SelfSignedCertificate `
        -DnsName "VaultRootCA" `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -KeyAlgorithm "RSA" `
        -KeyLength 4096 `
        -KeyExportPolicy Exportable `
        -KeyUsage CertSign, CRLSign, DigitalSignature `
        -Type Custom `
        -Subject "CN=VaultRootCA" `
        -TextExtension @(
            "2.5.29.19={critical}{text}CA=true"
        ) `
        -FriendlyName "VaultCACertificate"
    );

    # ---- Create self-signed certificate ---- #
    $VaultCertificate = (
        New-SelfSignedCertificate `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -KeyAlgorithm "RSA" `
        -KeyLength 4096 `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -Type Custom `
        -Subject "CN=localhost" `
        -Signer $VaultCACertificate `
        -TextExtension @(
            "2.5.29.17={text}dns=localhost&ipaddress=127.0.0.1&ipaddress=::1"
        ) `
        -FriendlyName "VaultCertificate"
    );

    $VaultCACertificate, $VaultCertificate | ForEach-Object {
        WritePEMEncodedCertKeyPair -certificate $_;
    };

} catch {
    Write-Output "Cert creation failed:"
    Write-Output $_;
    exit 1;
}

exit 0;
