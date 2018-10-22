#!/bin/sh

QUEUE_NUM=0
QUEUE_NAME=telegram

# first param = queue num
if [ -n "$1" ]; then
  QUEUE_NUM=$1
fi

echo "telegram setup"

TELEGRAM_DCS=$( cat <<- END
149.154.175.50
149.154.167.51
149.154.175.100
149.154.167.91
149.154.171.5
END
)

# int_to_ext

for telegram_dc in ${TELEGRAM_DCS}
do
  iptables -A ${QUEUE_NAME} -p tcp -s $telegram_dc --sport 443 -j NFQUEUE --queue-num ${QUEUE_NUM}
  iptables -A ${QUEUE_NAME} -p tcp -d $telegram_dc --dport 80 -j NFQUEUE --queue-num ${QUEUE_NUM}
  iptables -A ${QUEUE_NAME} -p tcp -s $telegram_dc --sport 5222 -j DROP
done


# Check outgoing tls connections to web.telegram.org
# only one application data packet going to web.telegram.org is allowed - all
# following packets will be blocked
iptables -A ${QUEUE_NAME} -p tcp --dport 443 -j NFQUEUE --queue-num ${QUEUE_NUM}

# all dns replies are checked for telegram servers
iptables -A ${QUEUE_NAME} -p udp --sport 53 -j NFQUEUE --queue-num ${QUEUE_NUM}
