# Insoc
# RHEL8 DNS + Logging Lab (Ready to use)

### On SERVER machine: 
#                  1) chmod +x setup-server.sh 
# command - DNS setup -     /usr/local/bin/setup-my-dns-and-logging-server.sh 192.168.29.206 server.example.com example.com (server ip) (fqdn) (domain name)
#                          /usr/local/bin/add-client.sh client99 192.168.29.199 (client name) (client ip)
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#  For Block --             sudo /usr/local/bin/admin-block-client.sh block <client-ip>
#    Unblock --           sudo /usr/local/bin/admin-block-client.sh unblock <client-ip>
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------



# On every CLIENT (once)
# 1) chmod +x join-client.sh
# 2) command  - /usr/local/bin/join-dns-and-enable-full-logging.sh 192.168.29.206 example.com client99 (server ip) ( domain) (client name) 



