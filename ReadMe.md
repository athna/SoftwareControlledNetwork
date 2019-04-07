# SoftwareControlledNetwork

The repository contains a Ryu-SDN controller based python code, inserting flows into Dataplane switches to grant connectivity between hosts across data-plane switches, based on Ethernet and VLAN protocol.

## Network layout
![](img/SDNNetworkLayout.png)

## Sytem setup
The network consists of 4 hosts, each running 2 VMs and a total of 6 OpenvSwitches, which are managed via an SDN controller. 2 out of the 6 switches are labeled as physical switches, whereas the remaining 4 switches are access switches. An access switch is a virtual switch hosted within a host to interconnect the two of its own VMs.

You can use any set of tools to implement the above network setup. For example, using Mininet, or by using Linux namespaces or LXC containers etc. alongwith OpenvSwitch.


## How to run the code
ryu-manager <file.py>

## How to test the code
### For 'L2_SDNcontrolled_RESTbased_vlan.py'
Use the following REST queries to put the hosts 1A and 3A under same VLAN-ID

curl -H "Content-Type: application/json" -X PUT -d '{"vlan":10}' http://localhost:8080/task2/port/1A
curl -H "Content-Type: application/json" -X PUT -d '{"vlan":10}' http://localhost:8080/task2/port/3A

The above commands use REST-API provided by 'l2_SDNcontrolled_RESTbased_vlan.py' to assign/remove/manage VLAN tags to indivdual hosts
