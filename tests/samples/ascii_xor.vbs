Dim filePath, fileNumber, content, fileLength, result
filePath = "C:\\tmp\file.txt"
fileNumber = FreeFile
Open filePath For Binary Access Read As #fileNumber
fileLength = FileLen(filePath)
WScript.Echo fileLength
ReDim content(fileLength - 1)
Get #fileNumber, , content
Close #fileNumber
WScript.Echo Join(content, vbNullChar)
result = content(0) Xor content(1)
WScript.Echo "result1: " & result
result = content(2) Xor content(3)
WScript.Echo "result2: " & result
