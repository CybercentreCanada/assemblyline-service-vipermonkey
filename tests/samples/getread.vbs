Dim fileNumber, content, fileLength
fileNumber = FreeFile
Open (ActiveDocument.FullName) For Binary As #fileNumber
fileLength = FileLen(ActiveDocument.FullName)
ReDim content(fileLength - 1)
Get #fileNumber, 1, content
WScript.Echo content
Close #fileNumber
WScript.Echo Join(content, vbNullChar)
