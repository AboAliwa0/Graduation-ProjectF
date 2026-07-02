@echo off
route ADD 10.129.137.215 MASK 255.255.255.255 192.168.192.1 METRIC 1 IF 68
echo.
if %ERRORLEVEL% EQU 0 (
  echo OK: TryHackMe route added
) else (
  echo FAILED: route exit code %ERRORLEVEL%
)
echo.
route print 10.129.137.215
echo.
pause
