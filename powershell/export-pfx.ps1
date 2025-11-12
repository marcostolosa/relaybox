# Change CN
$cert = Get-ChildItem Cert:\LocalMachine\my | Where Subject -Like "CN=castelblack.north.sevenkingdoms.local"
$mypwd = ConvertTo-SecureString -String '1234' -Force -AsPlainText
$params = @{
    Cert = 'Cert:\LocalMachine\my\' + $cert.Thumbprint
    FilePath = 'server.pfx'
    ChainOption = 'EndEntityCertOnly'
    NoProperties = $true
    Password = $mypwd
}
Export-PfxCertificate @params