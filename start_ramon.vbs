' Starts RAMON hidden, from the folder this file is in.
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = dir
sh.Run "pyw """ & dir & "\ramon_service.py""", 0, False
