route ADD 10.129.137.215 MASK 255.255.255.255 192.168.192.1 METRIC 1 IF 68 *> thm-route-admin.log
route print 10.129.137.215 >> thm-route-admin.log
Write-Host "Route command finished. Log written to thm-route-admin.log"
