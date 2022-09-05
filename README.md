Powershell Script Queries AD Computer's protocol setting (SMB/LDAP Signing, LLMNR, NetBIOS, NTLM)

This script began with 5 lines to query the SMB1 state of Windows Computers in an Actice Directory Environment. Over some months I added more queries, to get the state of SMB Signing, LDAP Signing, Link-local Multicast Name Resolution, NetBIOS and NTLM. It can be helpful for an overview o the hardening state. The results can be seen in a Grid and are exported to a csv-file.

I know it is not very graceful in that state, but it is not finished yet.



![Here an example for the results:](main/results001.JPG)