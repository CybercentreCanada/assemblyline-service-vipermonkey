Dim filePath, fileNumber, fileLength
filePath = "C:\tmp\file.txt"
fileNumber = FreeFile
Open filePath For Binary Access Read As #fileNumber
fileLength = FileLen(filePath)
WScript.Echo fileLength
