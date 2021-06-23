```bat
@REM set http proxy 127.0.0.1:1230
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d 127.0.0.1:1230 /f
@REM enable http proxy
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f
@REM run stn background
mshta vbscript:createobject("wscript.shell").run("stn.exe -c config.json",0)(window.close)
```
