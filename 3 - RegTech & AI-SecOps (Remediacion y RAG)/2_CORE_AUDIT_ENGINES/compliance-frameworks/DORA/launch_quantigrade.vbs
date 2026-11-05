Set WshShell = CreateObject("WScript.Shell")
' Run Streamlit using pythonw so the console window is hidden
' We specify the working directory implicitly by using the path of the script
scriptPath = Replace(WScript.ScriptFullName, WScript.ScriptName, ")
WshShell.CurrentDirectory = scriptPath
WshShell.Run "pythonw -m streamlit run dora_streamlit_app.py", 0, False
