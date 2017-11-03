<#
.SYNOPSIS
	This is a PowerShell script designed to send emails to random clients both within
	the associated domain and to pseudorandom users outside the domain to various
	external domains.

.DESCRIPTION
	The will send emails to users and requires input parameters to specify the station
	user's internal account email address and the external username username to be used
	with random external domains.

.PARAMETER in_usr
	This is the full username for the internal user from which emails will be sent when
	using MS Exchange.  NOTE: This user account must exist in Exchange in order to send
	emails.

.PARAMETER domain
	This is the AD domain where Exchange exists and where the username is a valid account
	holder.
	
.PARAMETER in_or_out
	This parameter tells the Send-Email function to use either an internal or external domain,
    and an associated text content makeup from the supplied email_corpus

.EXAMPLE
    This will send an email to an internal (domain) address using Exchange
    	Send-Email "adam.mcfarland" "3bct4id.army.mil" "internal"
    
    This usage will send an email using an external server based on the domain name supplied
        Send-Email "adamcfly" "facebook.com" "external"

.NOTES
    Revision History
        03/14/2017 : Bryan Scarbrough - Created
        05/01/2017 : Bryan Scarbrough - Added dot sourced Get-RandText.ps1 and Trim-Length.ps1
                                      - Exported user account list to separate text file
                                      - Created Send-Email function instead of running as
                                        standalone script
        05/08/2017 : Bryan Scarbrough - Added separate "Subject"/"Body" acquisition for email subject
#>

. "C:\scripts\Get-RandText.ps1"
. "C:\scripts\Trim-Length.ps1"

# Get DNS MX Record for associated domain
function Get-MX ($lookup) {
    [string]$record = nslookup -type=mx $lookup
    $mx = $record.split() | select-string -pattern $lookup
    return $mx[1]
}

# Get accounts to send emails to
function Get-Acct ($internal, $external, $max,
					$internal_acct="C:\scripts\txt-docs\internal_users.txt",
					$external_acct="C:\scripts\txt-docs\external_users.txt",
					$target_dom="C:\scripts\txt-docs\target_domains.txt") {

	$recipient = New-Object System.Collections.Generic.List[System.Object]
	[System.Collections.ArrayList]$internal_recipients = get-content $internal_acct

	[System.Collections.ArrayList]$external_recipients = get-content $external_acct

	# Domains to use for sending email (randomly selected if domain is external)
	$target_domains = get-content $target_dom
	
	# Make sure that at least one domain selection is made
	# DEFAULT is internal
	if (!($internal -Or $external)) {
		$internal = 1
	}

	# If both domains (external and internal) are selected, then distribute maximum
	# recipients between the two domains
	if (($internal -And $external) -And $max -eq 1) {
		$max = 2
		$int = get-random -minimum 1 -maximum $max
		$ext = $max - $int
	} elseif ($internal -And $external) {
		$int = get-random -minimum 1 -maximum $max
		$ext = $max - $int
	}
	else {
		$int = $max
		$ext = $max
	}
	
	# If sending to an internal email address then randomly select a user from the 
	# $internal_recipients text file
	if ($internal) {
		1..$int | % {
			$name = $internal_recipients | get-random
			$recipient.add("$name@$domain")
			$internal_recipients.remove($name)
		}
	}
	
	# If sending to an external email address then randomly select a user from the
	# $external_recipients text file
	if ($external) {
		1..$ext | % {
			$name = $external_recipients | get-random
			$ext_domain = $target_domains | get-random
			$recipient.add("$name@$ext_domain")
			$external_recipients.remove($name)
		}
	}

	return $recipient
}

# Get a random file name from the c:\scripts\attachments (default) folder to attach to email
function Get-Attachment ($num_attach,
                        $attachments_dir = "c:\scripts\attachments") {
	$attachments = New-Object System.Collections.Generic.List[System.Object]
	# Command to create attachments.txt files
	# get-childitem .\attachments -recurse | % { $_.fullname } >> attachments.txt
	[System.Collections.ArrayList]$attachment_list = get-childitem $attachments_dir -recurse | % { $_.fullname }
	if (!$num_attach -eq 0) {
		1..$num_attach | % {
			$attach = $attachment_list | get-random
			$attachment_list.remove($attach)
			$attachments.add($attach)
		}
	}
	
	return $attachments
}

function Send-Email ([string]$in_usr = "jim.davis",
	               [string]$domain = "3bct4id.army.mil",
                   [string]$in_or_out = "internal") {
    
    $num_recipients = 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5
    $num_attachments = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 3
    $attach_files = Get-Attachment ($num_attachments | get-random)
    [string]$from_domain = ""
    if ($domain -match "3bct4id") {
        $from_domain = "excg.3bct4id.army.mil"
    } else {
        $from_domain = (Get-MX $domain)
    }
    
	# If no attachments then do not declare them in the Mail_info object
	if ($attach_files) {
		$Mail_info = @{
			To = Get-Acct (get-random -maximum 2) (get-random -maximum 2) ($num_recipients | get-random)
			From = "$in_usr@$domain"
			Subject = (Get-RandText "$in_or_out" "subject" "US Army")
			Body = (Get-RandText "$in_or_out" "body" "US_Army")
			Attachments = $attach_files
			SmtpServer = $from_domain
		}
	} else {
		$Mail_info = @{
			To = Get-Acct (get-random -maximum 2) (get-random -maximum 2) ($num_recipients | get-random)
			From = "$in_usr@$domain"
			Subject = (Get-RandText "$in_or_out" "subject" "US Army")
			Body = (Get-RandText "$in_or_out" "body" "US_Army")
			SmtpServer = $from_domain
		}
    }
	
	# Send email using @mail_info data
    Send-MailMessage @Mail_info
}

# Example Usage - uncomment below to test
# Send-Email "adam.mcfarland" "3bct4id.army.mil" "internal"
# Send-Email "adamcfly" "facebook.com" "external"