
<#
.SYNOPSIS
	This is PowerShell script designed create and save MS Office documents.

.DESCRIPTION
	This script is used to create MS Word, Excel, and PowerPoint documents using random
    text information from both the Enron email_corpus (located at c:\scripts\email_corpus)
    and, in the case of PowerPoint populate slides with information from pre-created CSV
    files located at c:\scripts\csv-files and images located at c:\scripts\images.

.PARAMETER doc
	The document to open and/or print.

.PARAMETER print
	1/0 (true or false) value used to determine if opened document will be printed or not.
	
.EXAMPLE
    Open a Document
        Open-Print-Docs "C:\scripts\attachments\2012_ethics_training.pptx"
    
    Open a Document and Print it
    	Open-Print-Docs "C:\scripts\attachments\2012_ethics_training.pptx" 1

.NOTES
    Revision History:
        05/07/2017 : Bryan Scarbrough - Created
        
#>

function Open-Print-Docs ($doc, $print=0) {

    if ($print) {
        
        # Open document and print.
        # TO DO: Figure out how to print already opened document (current setup will
        # open document and print then immediately close document).
    	Start-Process -FilePath $doc -Verb Print -PassThru | % { sleep 30; $_ } | kill
    } else {
    
        # Open document and wait 5-20 min before closing
        Start-Process -FilePath $doc -PassThru | % { sleep (get-random -minimum 300 -maximum 1200); $_ } | kill    
    }

}
