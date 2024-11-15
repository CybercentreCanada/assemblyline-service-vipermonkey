Function AddTenToArray(ByVal arr)
    Dim i
    For i = 0 To UBound(arr)
        arr(i) = arr(i) + 10
    Next
End Function
Dim arr
arr = Array(5, 15, 25, 35, 45)
AddTenToArray(arr)
WScript.Echo arr
