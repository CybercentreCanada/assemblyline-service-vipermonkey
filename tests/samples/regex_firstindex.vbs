Dim str, regEx, matches, match, startIndex

str = "aaabbaaabbaaa"

Set regEx = New RegExp
regEx.Pattern = "bb"

Set matches = regEx.Execute(str)

For Each match In matches
    startIndex = match.FirstIndex
    WScript.Echo "match: " & startIndex
Next

