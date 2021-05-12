@echo off
copy MyNative.exe %systemroot%\System32\.
regedit /s add.reg
echo Native Example Installed
pause