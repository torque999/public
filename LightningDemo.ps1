<#
.SYNOPSIS
    Site creation and certificate binding.
.DESCRIPTION
    This script is used to create the websites needed for new clients.  It will then bind the client specific certificates.
.EXAMPLE
    New-SiteCreation -ID ABCD -Domain site.contoso.com -Pod 1 -ServerCount 8

    This command will copy the default site framework to the POD1 folder and name it ABCD, build the ABCD site in IIS,
    remove the .aspx handlers and bind the client specific certificate to the newly created site.
.NOTES

    Author:         Jayson Bennett
    Date:            4/24/2018
    Version 1.3
#>
#Requires -Version 5
#Requires -RunAsAdministrator
function New-SiteCreation {
    [CmdletBinding()]
    [Alias()]
    param(
        #ID of the client you are updating.
        [Parameter(Mandatory = $true)]
        [string]$ID,

        #Use fully qualified domain name for this entry
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        #POD that the client is assigend to.
        [Parameter(Mandatory = $true)]
        [Int]$Pod,

        #Number of servers in your farm.
        [Parameter(Mandatory = $true)]
        [Int]$ServerCount
    )
    
    Begin {
        #This is the list of servers in the farm.
        $Base = ($env:COMPUTERNAME).Substring(0, 3)
        $Source = $env:COMPUTERNAME
        $Farm = $ServerCount | ForEach-Object { "$($base)WEB0$_" }
        #This copies and renames the Framework folder to the FI specific directory.
        foreach ($Server in $Farm) {
            #We are checking to make sure you did your job and installed the certificate in the machine certificate store.
            $CertTest = Invoke-Command -ComputerName $Server -ScriptBlock { param ($Domain)
                Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.DnsNameList -match $Domain -and $_.notafter -gt (Get-Date) } 
            } -ArgumentList $Domain              
            If ($null -ne $CertTest) {
                #Copying over the default branding folder for the new sites.    
                Robocopy.exe "\\$Source\c`$\Default\Framework" "\\$Server\c`$\Branded\POD$Pod\$ID" -e /w:1 /r:5
            }
            Else {
                Throw "Check certificate installaton on $Server."
            }
        }
    }
    
    Process {
        #This section sets up the Splash site and removes the .aspx handlers.
        $Farm.ForEach( { Invoke-Command -ComputerName $_ -ScriptBlock { param ($ID, $Pod, $Domain)
                Import-Module WebAdministration
                <#
                    Building out the website, setting SSL and SNI flags, adding the host header, setting the physical path, building
                    and assigning the application pool and removing ASPX handlers.
                    #>
                New-Website $ID -port 443 -physicalPath C:\Branded\POD$Pod\$ID -Ssl -SslFlags 1 -HostHeader $Domain | Out-Null
                New-Item IIS:\AppPools\$ID
                Set-ItemProperty IIS:\Sites\$ID -Name applicationPool -Value $ID
                Remove-WebHandler -Name PageHandlerFactory-Integrated -PSPath IIS:\Sites\$ID
                Remove-WebHandler -Name PageHandlerFactory-Integrated-4.0 -PSPath IIS:\Sites\$ID
                Remove-WebHandler -Name PageHandlerFactory-ISAPI-2.0 -PSPath IIS:\Sites\$ID
                Remove-WebHandler -Name PageHandlerFactory-ISAPI-2.0-64 -PSPath IIS:\Sites\$ID
                Remove-WebHandler -Name PageHandlerFactory-ISAPI-4.0_32bit -PSPath IIS:\Sites\$ID
                Remove-WebHandler -Name PageHandlerFactory-ISAPI-4.0_64bit -PSPath IIS:\Sites\$ID
            } -ArgumentList $ID, $Pod, $Domain 
        })
    }
    
    End {
        #This section binds the certificates to the websites.
        $Farm.ForEach( { Invoke-Command -ComputerName $_ -ScriptBlock { param ($ID, $CertTest)
                Import-Module WebAdministration
                #Binds the thumbprint of the specific certificate and binds it to the 443 port for the host header.
                $FarmSite = Get-WebBinding -Name $ID
                $FarmSite.AddSslCertificate($CertTest.thumbprint, "My")
            } -ArgumentList $ID, $CertTest 
        })
    }
}