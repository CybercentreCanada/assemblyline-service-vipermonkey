# Dictionary of VBA commands

vba_builtins = {
    'Array': 'Returns a Variant containing an array.',
    'CallByName': 'Executes a method of an object, or sets or returns a property of an object.',
    'Chr': 'Returns a String containing the character associated with the specified character code. Can be used for obfuscation.',
    'Create': 'Typically used to create an object, search for "Create" in "vipermonkey_output.log" to find what object was created.',
    'CreateObject': 'Creates and returns a reference to an ActiveX object.',
    'CLng': 'Convert value to a long integer. Can be used for obfuscation.',
    'Get': 'Reads data from an open disk file into a variable.',
    'GetObject': 'Returns a reference to an object provided by an ActiveX component.',
    'Len': 'Returns a Long containing the number of characters in a string or the number of bytes required to store a variable.',
    'Log': 'Returns a Double specifying the natural logarithm of a number.',
    'Mid': 'Returns a Variant (String) containing a specified number of characters from a string. Can be used for obfuscation.',
    'MsgBox': 'Displays a message in a dialog box, waits for the user to click a button, and returns an Integer indicating which button the user clicked.',
    'Open': 'Enables input/output (I/O) to a file.',
    'Range': 'If using excel: Returns a Range object that represents a cell or a range of cells. Used with Sheets to access cells within workbooks',
    'Run': 'Runs a macro or calls a function. This can be used to run a macro written in Visual Basic or the Microsoft Office macro languages, or to run a function in a DLL or XLL.',
    'Sheets': 'A collection of all the sheets in the specified or active workbook. Can access information within workbooks to avoid detection.',
    'Shell': 'Runs an executable program and returns a Variant (Double) representing the program\'s task ID if successful; otherwise, it returns zero.',
}