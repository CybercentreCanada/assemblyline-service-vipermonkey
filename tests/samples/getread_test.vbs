Dim filePath, fileNumber, content, fileLength
filePath = "C:\\tmp\file.txt"
fileNumber = FreeFile
Open filePath For Binary Access Read As #fileNumber
fileLength = FileLen(filePath)
WScript.Echo fileLength
ReDim content(fileLength - 1)
Get #fileNumber, , content
WScript.Echo content
Close #fileNumber
WScript.Echo Join(content, vbNullChar)
