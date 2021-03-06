﻿
<#
.SYNOPSIS
	This is a PowerShell script that will shorten a desired string value to the designated
    length value.

.DESCRIPTION
	The script takes a string input and uses the join method to only append the desired
    number of characters to the resultant output value.  The script is designed to be
    used with the pipeline.

.PARAMETER Str
	This is the AD domain where Exchange exists and where the username is a valid account
	holder.
	
.PARAMETER length
	This is the username to be used with any external email domains when sending emails
	over the network.  This username can practically be anything a normal username can be
	(baring some special characters such as space, comma, greater-than, less-than,
	parenthesis, etc.).

.EXAMPLE
	Script can be used in standalone:
        Trim-Length "Some Text Input" 10
    
    Script can also be used in pipeline
        (Get-RandText "internal" "body" "US Army") | Trim-Length 10
 
.NOTES
    Revision History:
    	Created by : TechnoTone (StackHub - https://stackoverflow.com/questions/2336435/powershell-how-to-limit-string-to-n-characters)
        04/20/2017 : Bryan Scarbrough - Created.

#>

function Trim-Length {
    param (
        [parameter(Mandatory=$True,ValueFromPipeline=$True)] [string] $Str
      , [parameter(Mandatory=$True,Position=1)] [int] $Length
    )
        $Str[0..($Length-1)] -join ""
}
