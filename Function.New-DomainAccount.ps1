<#
.SYNOPSIS
    This function creates an Active Directory account
.DESCRIPTION
    Use this function to create an AD account for new users.
.EXAMPLE
    New-DomainAcount -Role Office -FirstName John -LastName Smith -username john.smith -password N3w@ccount!
    
    This will create the AD User account for John Smith
.NOTES
    Author:	    Jayson Bennett
    Date:	    3/27/2020
    Version:    1.0
#>
function New-DomainAccount
 {
    [CmdletBinding()]
    Param (
        # The region you are creating the account for
        [Parameter(Mandatory=$true)]
        [ValidateSet("IT", "Office")]
        $Role,
        
        # First name of the user
        [Parameter(Mandatory=$true)]
        $FirstName,
        
        # Last Name of the user
        [Parameter(Mandatory=$true)]
        $LastName,
        
        # Username of the service account
        [Parameter(Mandatory=$true)]
        $username,

        # The password that you created for this account and saved into KeePass
        [Parameter(Mandatory=$true)]
        $password
    )
    
    begin {#converts the password that was created into a secure string
        $securepassword = ConvertTo-SecureString $password -AsPlainText -Force
    }
    
    process {#Creates new user account and adds the account to the basic groups.  There is a back tick in the New-ADUser line for script readability
        New-ADUser -Server contoso.com -Path "ou=Users,dc=contoso,dc=com" -GivenName $FirstName -Surname $LastName -Name "$($FirstName) $($LastName)" -SamAccountName $username -UserPrincipalName $username@contoso.com `
        -DisplayName "$($FirstName) $($LastName)" -AccountPassword $securepassword -CannotChangePassword $false -PasswordNeverExpires $false -ChangePasswordAtLogon $false

        #Adds users to group memberships
        Add-AdGroupMember -Identity "All Users" -Server contoso.com -Members $username
        if ($Role -match "IT"){
            Add-ADGroupMember -Identity "IT Users" -Server contoso.com -Members $username   
         }
         else{
            Add-ADGroupMember -Identity "Office Users" -Server contoso.com -Members $username
         }
         Enable-ADAccount -Server contoso.com -Identity $username
    }
    
    end {#Dumps account information to confirm that it is saved to give to the new user
        $User = Get-ADUser -Server ec.contoso.com -Identity $username
        $props = [ordered] @{
            Name = $User.Name
            UserName = $User.samaccountname
            OU = $User.DistinguishedName.Split(',')[1,2]
            Enabled = $User.Enabled
            Password = $password
        }
        [PSCustomObject]$props | Format-List
    }
}