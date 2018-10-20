#!/bin/bash
#script to configure and start detector
#requires libnfnetlink libmnl and libnetfilter_queue

echo "Killing old detectors"
killall det
echo
echo


echo "Configuring interfaces..."
#configure interfaces
./host_config/reset_host.sh
./host_config/mobile_router_nat.sh
echo
echo

iptables --flush

echo "Running test specific setup"
if [ -z "$1" ]
then
  echo "No test name given - starting accept_all queue"
  ./build/det 0
else
  if [ "$1" == "all" ]; then
    # start detector for all tests and backend
    #
    # starts the det-program for each test - iptables ensures
    # each test-specific chain will be called with the incoming packet
    # the test-specific chain (configured in configurations/testname.sh)
    # redirects the packet to the responsible det program.
    #
    # The ACCEPT_PACKET makro in det should only set RETURN on the packet,
    # so it will traverse all other test-chains aswell
    #
    echo "Starting detector for all tests"
    echo "" > output.txt

    queue_num=0
    for test_configuration in `ls ./configurations/`; do
      testname=${test_configuration%.*}
      echo "starting ${testname} with queue ${queue_num}"

      #iptables setup (create queue and add to forward)
      iptables -N ${testname}
      iptables -A FORWARD -j ${testname}

      ./configurations/${testname}.sh ${queue_num}
      echo;echo
      echo "Starting detector..."
      ./build/det ${queue_num} ${testname} & >> output.txt

      queue_num=$(($queue_num+1))
    done

    # view logfile
    tail -f output.txt
  else
    # start specific test alone
    #redirect forward queue to test queue
    iptables -N $1
    iptables -A FORWARD -j $1

    ./configurations/$1.sh

    echo;echo
    echo "Starting detector..."
    ./build/det 0 $1
  fi
fi
