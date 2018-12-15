### SDN
this is a SDN project implemented on virtual enviroment.
Environment: mininet + ryu
I realized shortest path control in ryu with a topology discovery module

#### commands to run:
**terminal1:** 
cd ryu/ryu/app     # where you put your code
ryu-manager --observe links spcontrol.py

**terminal 2**
cd mininet/custom  # put your code here
sudo mn --controller remote --custom mytopo.py --topo topo

**terminal 3**
check flow tables
sudo ovs-ofctl -O OpenFlow13 dump-flows s1 
