# Security Advisory 


Common Vulnerabilities and Exposures 



| CVE           | TODO |
|--------------:| :------------------ |
| Date:         | 2019-03-06 00:20:00 UTC |
| Severity:     | Critical |
| References:   | [Twitter][BUG-2019-0001] |
| Exploit:      | [expl0itz][BUG-2019-0001 Exploit 1] |
| Impact:       | Remote Code Execution |
| Description:  | Ghidra opens up JDWP in debug mode listening on port 18001, you can use it to execute code remotely  |
| Fix:          | to fix change line 150 of `support/launch.sh` from `*` to `127.0.0.1`  |
| Mitigation:   | `iptables -A INPUT -p tcp --dport 18001 -s 127.0.0.1 -j ACCEPT`<br />`iptables -A INPUT -p tcp --dport 18001 -j DROP`


[BUG-2019-0001]: https://twitter.com/hackerfantastic/status/1103087869063704576
[BUG-2019-0001 Exploit 1]: http://web.archive.org/web/20190306220416/https://static.hacker.house/releasez/expl0itz/jdwp-exploit.txt
