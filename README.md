# Insoc
# RHEL8 DNS + Logging Lab (Ready to use)

## Repository Structure 

    Insoc/
    ├── setup-server.sh          # Full server installer (its only install on server)
    ├── join-client.sh           # Client join script (only install on client)
    ├── README.md                # This file
    └── LICENSE                  # GNU General Public License v3


### On SERVER machine:
    1) cd /usr/local/bin
    2) wget https://raw.githubusercontent.com/brinsko/Insoc/main/setup-server.sh -O setup-server.sh
    3) chmod +x setup-server.sh
    4) DNS setup -     /usr/local/bin/setup-server.sh  192.168.29.206 server.example.com example.com (server ip) (fqdn) (domain name)
                          /usr/local/bin/add-client.sh client99 192.168.29.199 (client name) (client ip)
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    For Block --             sudo /usr/local/bin/admin-block-client.sh block <client-ip>
    Unblock --           sudo /usr/local/bin/admin-block-client.sh unblock <client-ip>
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    For watch logs --     ls /var/log/remote
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------    


# On every CLIENT (once)
    1) cd /usr/local/bin 
    2) wget https://raw.githubusercontent.com/brinsko/Insoc/main/join-client.sh -O join-client.sh
    3) chmod +x join-client.sh
    4)  command  - /usr/local/bin/join-client.sh 192.168.29.206 example.com client99 (server ip) ( domain) (client name) 



