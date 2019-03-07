# Security Advisory 


Common Vulnerabilities and Exposures 



| CVE           | 2019-1 |
|--------------:| :------------------ |
| Date:         | 2019-03-06 00:20:00 UTC |
| Severity:     | Critical |
| References:   | [Twitter][CVE-2019-03-06-0020] |
| Exploit:      | [expl0itz][CVE-2019-03-06-0020 Exploit 1] |
| Impact:       | Remote Code Execution |
| Description:  | Ghidra opens up JDWP in debug mode listening on port 18001, you can use it to execute code remotely  |
| Fix:          | to fix change line 150 of `support/launch.sh` from `*` to `127.0.0.1`  |
| Mitigation:   | `iptables -A INPUT -p tcp --dport 18001 -s 127.0.0.1 -j ACCEPT`<br />`iptables -A INPUT -p tcp --dport 18001 -j DROP`


[CVE-2019-03-06-0020]: https://twitter.com/hackerfantastic/status/1103087869063704576
[CVE-2019-03-06-0020 Exploit 1]: https://static.hacker.house/releasez/expl0itz/jdwp-exploit.txt
