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
