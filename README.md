# ssh-fwd
Permit only ssh to github server

`iptables -D OUTPUT -s 172.29.8.21 -p tcp --dport 22 -j NFQUEUE --queue-num 1`
