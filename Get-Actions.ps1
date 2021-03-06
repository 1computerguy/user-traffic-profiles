<#
.SYNOPSIS
	This is a PowerShell script to be used with all of the dot sourced scripts to simulate
    real user activity in a Windows environment.

.DESCRIPTION
	This brings together several other scripts in an attempt to simulate real user activity.
    The activity involves functions like opening/closing documents, printing documents, sending/
    receiving email, creating MS Office documents, and surfing the "web" through Internet Explorer.
    The script uses multhreaded operations in order to allow script functions to run simultaneously
    similar to how a real user might use his/her computer.  Each user function has a built-in stop
    method that stops that particular function at some point to simulate the user no longer
    performing that function (this prevents a single user from printing or creating hundreds of
    documents in the course of a short time frame).  Each user will only be logged in for a random
    duration between 30 min and 2 hours at which point they will be logged out and another user
    automatically logged into the system.

.PARAMETER 
    None

.EXAMPLE
    Script is intended to be run on login
    	.\Get-Actions.ps1

.NOTES
    Revision History
        05/08/2017 : Bryan Scarbrough - Created
#>

function Get-Actions ( $open_doc=0,
					   $create_doc=0,
					   $print_doc=0,
					   $check_email=0,
					   $sr_email=0,
					   $web=0 ) {

    # Open and close office documents
    if ($open_doc) {
    
        # Run as separate script thread
        Start-Job -ScriptBlock {
			# Import Open-Print-Docs.ps1 script into job instances
			. "C:\scripts\Open-Print-Docs.ps1"
            
			$open_docs = $true
            while ( $open_docs ) {
            
                # Check My Documents folder for any available created documents.  If available
                # then add them to the potential open queue based on the random count selected
                # in the if statement below.  Otherwise use the c:\scripts\attachments folder                $MyDocsIsEmpty = [Environment]::GetFolderPath("MyDocuments") | Measure-Object
                if (($MyDocsIsEmpty.count -ne 0) -and ((get-random 10) -gt 7)) {
                    $MyDocsFolder = [Environment]::GetFolderPath("MyDocuments")
                    $doc = (Get-ChildItem $MyDocsFolder -recurse | % { $_.fullname }) | get-random
                } else {
                    $doc = (Get-Content "C:\scripts\txt-docs\attachments.txt") | get-random
                }
                Open-Print-Docs "$doc"
                
                # Sleep between 10-30 min between printing jobs.  If random value is
                # between 1000 and 1020 then user will stop printing.
                $sleep_time = (get-random -minimum 600 -maximum 1800)
                if (($sleep_time -lt 1050) -and ($sleep_time -gt 1020)) {
                   $open_docs = $false
                } else {
                    sleep $sleep_time
                }
            }
        }
    }
    
    # Create new Microsoft Office documents randomly selected from
    # the $doc_type array below
    if ($create_doc) {
    
        Start-Job -ScriptBlock {
			# Import Create-Office.ps1 for use within job instances
			. "C:\scripts\Create-Office.ps1"
			
		    $create_docs = $true
        	while ($create_docs) {
            	$doc_type = "word", "excel", "ppt"
				Create-Office ($doc_type | get-random)

                # Sleep between 10-30 min between printing jobs.  If random value is
                # between 1000 and 1020 then user will stop printing.
                $sleep_time = (get-random -minimum 600 -maximum 1800)
                if (($sleep_time -lt 1050) -and ($sleep_time -gt 1020)) {
                   $create_docs = $false
                } else {
                    sleep $sleep_time
                }
			}
        }
    }
    
    # Print existing documents located either in the user's My Documents folder, or
    # from the "c:\scripts\attachments" folder - documents are randomly selected
    if ($print_doc) {

        # Run as separate script thread
        Start-Job -ScriptBlock {
		
			# Import Open-Print-Docs.ps1 script into job instances
			. "C:\scripts\Open-Print-Docs.ps1"
			
            $print_docs = $true
            while ($print_docs) {
            
                # Check My Documents folder for any available created documents.  If available
                # then add them to the potential print queue based on the random count selected
                # in the if statement below.  Otherwise use the c:\scripts\attachments folder
                $MyDocsIsEmpty = [Environment]::GetFolderPath("MyDocuments") | Measure-Object
                if (($MyDocsIsEmpty.count -ne 0) -and ((get-random 10) -gt 7)) {
                    $MyDocsFolder = [Environment]::GetFolderPath("MyDocuments")
                    $doc = (Get-ChildItem $MyDocsFolder -recurse | % { $_.fullname }) | get-random
                } else {
                    $doc = (Get-Content "C:\scripts\txt-docs\attachments.txt") | get-random
                }
               
                Open-Print-Docs "$doc" 1
                
                # Sleep between 20-60 min between printing jobs.  If random value is
                # between 2980 and 3000 then user will stop printing.
                $sleep_time = (get-random -minimum 1200 -maximum 3600)
                if (($sleep_time -lt 3000) -and ($sleep_time -gt 2980)) {
                   $print_docs = $false
                } else {
                    sleep $sleep_time
                }
            }
        }
    }
    
    # User only "checks" email which means they only open MS Outlook.
    # TO DO: Have user open new emails, select different folders and
    # move messages from one folder to another
    if ($check_email) {
    
        # Run as separate script thread
        # Open MS Outlook to simulate user checking email
        Start-Job -ScriptBlock {
		    $Outlook = New-Object -ComObject Outlook.Application
			$Namespace = $Outlook.GetNamespace("MAPI")
			$Folder = $Namespace.GetDefaultFolder("olFolderInbox")
			$Explorer = $Folder.GetExplorer()
			$Explorer.Display()
		}
    }
    
    # User sends and receives email
    if ($sr_email) {
        
        # Run as separate script thread
        # Use the Send-Email function to send email as currently logged in user
        Start-Job -ScriptBlock {
		
        	# Open MS Outlook to simulate user checking email
			$Outlook = New-Object -ComObject Outlook.Application
			$Namespace = $Outlook.GetNamespace("MAPI")
			$Folder = $Namespace.GetDefaultFolder("olFolderInbox")
			$Explorer = $Folder.GetExplorer()
			$Explorer.Display()
			
			# Import Send-Email.ps1 script into job instance
			. "C:\scripts\Send-Email.ps1"
			
            # CSV file mapping internal user accounts to an associated external
            # username and domain for sending and receiving emails
            $Input_File = "C:\scripts\txt-docs\internal-to-external.csv"
            $Internal_user = $env:UserName
            $Internal_domain = $env:UserDomain
            
            $Accounts = Import-Csv -Path "$Input_File"
            $External_user = ($Accounts | ? { $_.internal -eq $Internal_user }).external
            $External_domain = ($Accounts | ? { $_.internal -eq $Internal_user }).domain
            
            # Begin sending emails.  Use get-random to determine if email is sent internally
            # - through Exchange, or externally - through associated user's external username
            # and domain
            $sr = $true
            while ($sr) {
                if ((get-random 10) -lt 7) {
                    Send-Email $Internal_user $Internal_domain "internal"
                } else {
                    Send-Email $external_user $external_domain "external"
                }
                
                # Sleep from 5-15 min between sending emails
                sleep (get-random -minimum 300 -maximum 900)
                
                # If value of 25 is reached from get-random then all user will stop emailing
                if ((get-random 100) -eq 25) {
                    Close-All
                    $sr = false
                }
            }
        }
    }
    
    # User will open Internet Explorer and open/close various websites in the browser
    if ($web) {
        Start-Job -ScriptBlock {
			
			# Import Trim-Length.ps1 and Add-IETab.ps1 scripts for use within
			# job instance
			. "C:\scripts\Trim-Length.ps1"
			. "C:\scripts\Add-IETab.ps1"

            $urls="c:\scripts\txt-docs\urls.txt"
            $surf = $true
            while ($surf) {
                # If get-random returns value greater than 7 then browser tabs will be
                # enumerated and random tabs closed.  Otherwise new tabs will be opened.
            	if ((get-random 10) -lt 7) {
            		$link = get-content $urls | get-random
            		Open-IE $link
                } else {
                    Get-Tabs | Open-IE (? { $_.Title -match ($_.Title | Trim-Length 8) }) 1
                }
                
                # Wait from 1-5 min between web actions
                sleep (get-random -minimum 60 -maximum 300)
                
                # If value of 25 is reached from get-random then all browser tabs will be
                # closed out and user will stop navigating the web
                if ((get-random 100) -eq 25) {
                    Close-All
                    $surf = false
                }
            }
        }
    }
    
    # Sleep for 30min to 2hrs and allow "normal" user activity
    sleep (get-random -minimum 1800 -maximum 7200)
 
    # Close all applications
    (get-process | ? { $_.mainwindowtitle -ne "" -and $_.processname -ne "powershell" } ) | stop-process
    
    # Call the AutoLogin.ps1 script
    &"C:\scripts\Auto-Login.ps1"
    
    # Logout so new user can log in
    (Get-WmiObject -Class Win32_OperatingSystem).Win32Shutdown(0)
}

# Make sure the user is doing something on the system
do {
	$open = (get-random 2)
	$create = (get-random 2)
	$print = (get-random 2)
	$check = (get-random 2)
	$sr = (get-random 2)
	$surf_web = (get-random 2)
	
	# Make sure that Send/Receive and Check email are not selected at the same time
	# to prevent multiple MS Outlook instances from opening
	if ($sr) {
		$check = 0
	}
} while ($open -eq 0 -and $create -eq 0 -and $print -eq 0 -and $check -eq 0 -and $sr -eq 0 -and $surf_web -eq 0)

# Call Get-Actions function to start script operations using random activity values above
Get-Actions $open $create $print $check $sr $surf_web
