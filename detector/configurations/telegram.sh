#!/bin/sh


echo "telegram setup"

TELEGRAM_DCS=$( cat <<- END
149.154.175.50
149.154.167.51
149.154.175.100
149.154.167.91
149.154.171.5
END
)

iptables --flush

# int_to_ext

for telegram_dc in ${TELEGRAM_DCS}
do
  iptables -A FORWARD -p tcp -s $telegram_dc --sport 443 -j NFQUEUE --queue-num 0
  iptables -A FORWARD -p tcp -d $telegram_dc --dport 80 -j NFQUEUE --queue-num 0
done


# Check outgoing tls connections to web.telegram.org
# only one application data packet going to web.telegram.org is allowed - all
# following packets will be blocked
iptables -A FORWARD -p tcp --dport 443 -j NFQUEUE --queue-num 0

# all dns replies are checked for telegram servers
iptables -A FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 0
