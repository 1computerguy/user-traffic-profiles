<#
.SYNOPSIS
	This is PowerShell script designed create and save MS Office documents.

.DESCRIPTION
	This script is used to create MS Word, Excel, and PowerPoint documents using random
    text information from both the Enron email_corpus (located at c:\scripts\email_corpus)
    and, in the case of PowerPoint populate slides with information from pre-created CSV
    files located at c:\scripts\csv-files and images located at c:\scripts\images.

.PARAMETER doc_type
	The type of document to create.  Acceptable values are "word", "excel", "ppt".

.PARAMETER folder
	This is the folder path used to save documents.  Default value is My Documents.
	
.PARAMETER filename
	This is the filename used to save the document.  The default value is a random string
    of 6 characters obtained from the email_corpus and the current date in a yyyyMMddHHmmss
    format.

.PARAMETER data_file
    This is the location of the CSV file used to populate a PowerPoint presentation.  If null
    then the value is a randomly selected file from the c:\scripts\csv-files folder.

.EXAMPLE
    Create an MS Word document
    	Create-Office "word"
        
    Create an MS Excel document and save to a custom directory
        Create-Office "excel" "C:\scripts\temp"

.NOTES
    Revision History:
        05/04/2017 : Bryan Scarbrough - Created
        05/06/2017 : Bryan Scarbrough - MS Excel document capability added
        05/07/2017 : Bryan Scarbrough - MS PowerPoint document capabilitiy added

#>

. "C:\scripts\Get-RandText.ps1"
. "C:\scripts\Trim-Length.ps1"

function Create-Office ($doc_type,
                        $folder = [Environment]::GetFolderPath("MyDocuments"),
                        $filename = (Get-RandText "internal" "subject" "US Army" | Trim-length 6),
                        $data_file = $null
                        ) {
                        
    Add-type -AssemblyName office
    $Date = (Get-Date -Format yyyyMMddHHmmss).toString()
    
    ## CREATE WORD DOCUMENT ##
    if ($doc_type -cmatch "word") {
        ## UNCOMMENT THE BELOW LINES FOR TESTING ##
        ## $Date = (Get-Date -Format yyyyMMddHHmmss).toString()
        ## Add-type -AssemblyName office
        ## $folder = [Environment]::GetFolderPath("MyDocuments")
        
        # Create MS Word object instance
        $Word = New-Object -ComObject Word.Application
        $Word.Visible = $True
        $WDocument = $Word.Documents.Add()
        $Selection = $Word.Selection
        
        # Select the number of paragraphs and the number of "lines" per paragraph
        # These values are used in the foreach loops below
        $num_of_paragraphs = get-random -minimum 2 -maximum 4
        $num_of_lines = get-random -minimum 1 -maximum 3

        # Iterate over the number of lines and paragraphs
        0..$num_of_paragraphs | % {
            $Selection.TypeParagraph()
            0..$num_of_lines | % {
            
                # Write text to the file
                $Selection.TypeText((Get-RandText "internal" "body" "US Army"))
                
                # Sleep between 30 seconds and 3 minutes to add realistic delay
                sleep (get-random -minimum 20 -maximum 180)
            }
        }

        # Create variables for filename and folder location and save document.
        # Once saved, then exit all instances.
        $FullName = "$FileName - $Date.doc"
        $Output = "$Folder\$FullName"
        $WDocument.SaveAs([ref]$Output,[ref]$SaveFormat::wdFormatDocument)
        $Word.Quit()
        $Word = $null
    }
    
    ## CREATE EXCEL SPREADSHEET ##
    if ($doc_type -cmatch "excel") {
        ## UNCOMMENT THE BELOW LINES FOR TESTING ##
        ## $Date = (Get-Date -Format yyyyMMddHHmmss).toString()
        ## Add-type -AssemblyName office
        ## $folder = [Environment]::GetFolderPath("MyDocuments")
        
        # Create MS Excel object instance
        $Excel = New-Object -ComObject Excel.Application
        $Excel.Visible = $True
        $Workbook = $Excel.Workbooks.Add()
        $Sheet = $Workbook.WorkSheets.item("sheet1")
        $Sheet.activate()
        
        # Determine maximum number of rows and columns for spreadsheet
        $max_rows = get-random -minimum 10 -maximum 100
        $max_columns = get-random -minimum 5 -maximum 15
        
        # Iterate over rows and columns and split message text into an array
        # Then insert each value of the array into a row in the spreadsheet
        1..($max_rows+1) | % {
            $data = (Get-RandText "internal" "body" "US Army").split()
            $data = $data | ?{$_}
            $row = $_
            1..($max_columns+1) | % {
                $Sheet.Cells.Item($row,$_) = $data[$_-1]
            }
            
            # Sleep between 30 seconds and 3 minutes to add realistic delay
            sleep (get-random -minimum 20 -maximum 180)
        }

        # Create variables for filename and folder location and save document.
        # Once saved, then exit all instances.        
        $FullName = "$Filename - $Date.xls"
        $Output = "$Folder\$FullName"
        $Sheet.SaveAs($Output)
        $Excel.Quit()
        $Excel = $null
    }
    
    ## CREATE POWERPOINT PRESENTATION ##
    if ($doc_type -cmatch "ppt") {
        ## UNCOMMENT THE BELOW LINES FOR PPT CREATION TESTING ##
        ## $Date = (Get-Date -Format yyyyMMddHHmmss).toString()
        ## Add-type -AssemblyName office
        ## $folder = [Environment]::GetFolderPath("MyDocuments")
        
        # Check data_file value and if null get random file from c:\scripts\csv-files
        if ($data_file -eq $null) {
            $InputFile = get-childitem 'c:\scripts\csv-files\' | % {$_.fullname} | get-random
        } else {
            $InputFile = $data_file
        }
        
        # Import and parse CSV file to get values to use for slide Title and Slide Body
        $CSV_file = Import-Csv -Path "$InputFile"
        $Title = ($CSV_file | Get-member -MemberType 'NoteProperty' | Select-Object -ExpandProperty 'Name')[1]
        $Body =  ($CSV_file | Get-member -MemberType 'NoteProperty' | Select-Object -ExpandProperty 'Name')[0]
        
        # Create True/False values for PPT
        $MSTrue=[Microsoft.Office.Core.MsoTriState]::msoTrue
		$MsFalse=[Microsoft.Office.Core.MsoTriState]::msoFalse
        
        # Create MS PowerPoint object instance
        $PowerPoint = New-Object -ComObject Powerpoint.Application
        $PowerPoint.Visible = $MSTrue
        $Presentation = $PowerPoint.Presentations.Add()
        $SlideType = “microsoft.office.interop.powerpoint.ppSlideLayout” -as [type]
        
        # Define slide layout types to use for presentation
        $slide_type_title = $SlideType::ppLayoutTitle
        $slide_type_chart = $SlideType::ppLayoutChart
        $slide_type_text = $SlideType::ppLayoutText
        
        # Create presentation and add first slide as title type using
        # CSV Title and Body values from above
        $Slide = $Presentation.slides.Add(1,$slide_type_title)
		$Slide.Shapes.Title.TextFrame.TextRange.Text = $Title
		$Slide.shapes.item(2).TextFrame.TextRange.Text = $Body
        $Slide.BackgroundStyle = 11
        
        # Increment slide number, then iterate over CSV object creating
        # slides and populating them with the CSV file data and random
        # images from the c:\scripts\images folder
        $slide_num = 2
        $CSV_file | ForEach-Object {
            # If get-random returns a value greater than 7, then an image slide is
            # added to the presentation, otherwise create text only slides
            if ((get-random 10) -gt 7) {
                $Image = get-childitem 'c:\scripts\images\' | % {$_.fullname} | get-random
                $Slide = $Presentation.Slides.Add($slide_num, $slide_type_chart)
                $Slide.BackgroundStyle = 11
                $Slide.Shapes.title.TextFrame.TextRange.Text = $_.$Title
                $Slide.Shapes.AddPicture($Image, $MSFalse, $MSTrue, 200, 400)
				
				# Sleep from 10-100 seconds to add user realism to slide creation
                sleep (get-random -minimum 10 -maximum 100)
            } else {
                $Slide = $Presentation.slides.Add($slide_num, $slide_type_text)
                $Slide.BackgroundStyle = 11
                $Slide.Shapes.title.TextFrame.TextRange.Text = $_.$Title
                $Slide.Shapes.item(2).TextFrame.TextRange.Text = $_.$Body
				
				# Sleep from 10-100 seconds to add user realism to slide creation
                sleep (get-random -minimum 10 -maximum 100)
            }
            
            # Increment slide number for next slide to add
            $slide_num ++
        }

        # Create variables for filename and folder location and save document.
        # Once saved, then exit all instances.
        $FullName = "$Filename - $Date.ppt"
        $Presentation.SavecopyAs("$Folder\$Fullname")
        $Presentation.Close()
        $PowerPoint.Quit()
        $PowerPoint = $null
        Stop-Process -name "POWERPNT"
    }
    
    # Perform garbage collection - required to completely stop some processes and
    # clear memory buffers appropriately.
    [gc]::collect()
    [gc]::WaitForPendingFinalizers()
}

#Create-Office "word"
#Create-Office "excel"
#Create-Office "ppt"