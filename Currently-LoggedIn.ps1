<#
.SYNOPSIS
	This is a PowerShell script to search a Microsoft Windows Active Directory Domain.

.DESCRIPTION
	This script enumerates lastloggedin time and if it is more than 2 hours behind the current
    time (the maximum time a user will be logged in in the CyberQuest Network) then the account
    is added to an array and returned for available user selection.

.PARAMETER user_file
	The user_file parameter is a line delimted file list of useable Active Directory user
    accounts.

.EXAMPLE
    This will return the entire list of available login accounts
    	Get-NextLogin "C:\scripts\txt-docs\user_accounts.txt"
    
    A more usable method is to couple the Get-NextLogin function with get-random to return a
    single account with which to login to the system
        get-random (Get-NextLogin "C:\scripts\txt-docs\user_accounts.txt")

.NOTES
    Revision History
        05/01/2017 : Bryan Scarbrough - Created
        05/09/2017 : Bryan Scarbrough - Moved else statement out to first IF in order to grab
                                        all available user accounts
#>

function Get-NextLogin ($user_file) {

    # Create some variables and placeholders
	$potential_login = @()
	$user_data = Get-Content $user_file
	$searcher = New-Object DirectoryServices.DirectorySearcher([adsi]"")
    
    # Iterate over the user_data contents (these are the known user accounts to enumerate)
	$user_data | % {
        # Filter on SAMAccountName and get all account attributes
		$searcher.filter = "(&(objectCategory=Person)(objectClass=User)(SAMAccountName=$_))"
		$users = $searcher.findall()
		
        # Iterate over located users
		$users | % {
        
            # If user has never logged in then lastlogon value will be 0, thus user is added
            # to the $potential_login list
			if ($_.properties.item("lastlogon") -ne 0) {
                
                # If user has logged in, but their last login was more than 2 hours ago then
                # they are also added to the $potential_login user list
				$time = [datetime]::FromFileTime([int64]::Parse($_.properties.item("lastlogon")))
				if ((get-date).AddHours(-2) -gt $time) {
					$potential_login += $_.properties.item("SAMAccountName")
				}
			} else {
                $potential_login += $_.properties.item("SAMAccountName")
            }
		}
	}
    # Return list of potential users - often used with get-random to randomly select
    # the next login user.  See NOTES above for example syntax.
	return $potential_login
}
