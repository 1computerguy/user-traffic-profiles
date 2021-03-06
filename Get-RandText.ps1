
<#
.SYNOPSIS
	This is PowerShell script designed to get random text from a series of email messages
    from the Enron email corpus (located at .\email_corpus"

.DESCRIPTION
	The script selects a random file path from a text file and then gets the content of the
    selected file at the designated location.  There are both "internal" and "external" file
    paths for use with Spam and external emails as well internall corporate styled emails for
    creating more internalized documents and email messages.

.PARAMETER message_type
	This is the type of message to generate, whether internal or external.

.PARAMETER message_part
    This variable is used to establish which part of the message to use for the email. The
    acceptable values are "body" for an actual email message body, and "subject" to use a
    message subject line.
    
.PARAMETER company_replace
	This is the name to be used in place of every Enron reference throughout the documents.
    This value is used to help add "personalization" to the document data to make it appear
    more applicable to your environment.
	
.EXAMPLE
    Long form usage with explicit argument declaration
	Get-RandText -message_type "internal" -message_part "subject" -company_replace "US Army"
    
    Short form with implicit argument declaration
    Get-RandTextd "internal" "subject" "US Army"
#>

# Get-RandText function to generate randomly selected text from the Enron email_corpus
# by default
function Get-RandText ($message_type, $message_part, $company_replace) {
	
	# Using system.io.file::readalllines as opposed to get-content for speed and memory consumption
    $count = ([System.IO.File]::ReadAllLines("C:\scripts\txt-docs\$message_type.txt")).count
    
	# Go through loop at least once in order to grab email subject or body depending on 
	# $message_type variable defined above
    $StopLoop = $false
    do {
        try {
            if ($message_part -eq "body") {
				# Grab text from randomly selected path and replace any "Enron" reference with
				# $company_replace data to customize message content
                [string]$message = (get-content (([System.IO.File]::ReadAllLines("C:\scripts\txt-docs\$message_type.txt"))[(get-random -minimum 1 -maximum $count)])  | select-object -skip 7 | ? {$_ -ne ""}) | % { $_ -replace '[Ee][Nn][Rr][Oo][Nn]',$company_replace } -ErrorAction SilentlyContinue
			
			# If $message_part is "subject" then only get the subject line of a randomly selected
			# message
            } elseif ($message_part -eq "subject") {
                [string]$message = (get-content (([System.IO.File]::ReadAllLines("C:\scripts\txt-docs\$message_type.txt"))[(get-random -minimum 1 -maximum $count)])  | select-object) | ? { $_ -match 'Subject:' } | select -First 1 | % { $_ -replace 'Subject:', '' }
            }
			
			# If data is obtained without error then exit the loop
            $StopLoop = $true
        }
		# Not worried about error, just want to continue until finished
        catch {
        }
    } while ($StopLoop -eq $false)
    
    return $message
}

# Example usage - uncomment below to test
#Get-RandText -message_type "internal" -message_part "subject" -company_replace "US Army"
#Get-RandText "internal" "body" "US_Army"