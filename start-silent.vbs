Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "electron.exe . --no-sandbox", 0, False
