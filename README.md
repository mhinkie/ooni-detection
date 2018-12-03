# ooni-detection
Middlebox for detecting and manipulating OONI tests

## Detector
The detector is based on Netfilter's queue functionality. In my experiments it is run on a router, 
which will inspect all traffic associated with the targeted application using the FORWARD chain. The 
detector can currently be started for either the Facebook messenger test, the Whatsapp test, or the 
Telegram test.

The detector is run via deploy.sh:
 - compiles the detector program using cmake
 - copies files to the router (in my experiments an Ubuntu VM)
 - configures interfaces (using vm_config/...)
 - calls test-specific iptables-setup (see configurations/...)
 - starts the detector program
 
## Goal
The detector tries to detect packets associated with OONI on the network and gives information on 
which hosts were identified as OONI probes. It also blocks the targeted application in a way that 
is not noticable by the examined OONI probe version.
Therefore OONI will think no blocking or manipulation is performed, while the application is still unusable.
