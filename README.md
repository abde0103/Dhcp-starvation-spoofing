# Aim

The objective of this project is to starve a dhcp server : run it out of all its available ip adresses and then usurp the identity of a dhcp server to give legitimate clients fake ip adresses and malicious informations: We can set the ip address of the attacker as a router in the offer packet. Thus, all the client traffic will pass by the attacker machine.



## Starvation 

The program starvation.c sends a huge number of broadcasted discover packets in the network set to "enp0s8" here. The dhcp server resends back offer packets till it has no more available ip addresses: we know that there is a lease time after sending an offer packet : a duration in which the ip address offered is reserved.

When the pool of ip addresses is empty, if a  legitimate client tries to connect to this network, he will not be able because the dhcp server has no ip addresses to assign.

## Dhcp usurpation

dhcp_usurpation.c detects the first discover packet sent in the network from 0.0.0.0 to 255.255.255.255 then it sends an offer packet with fake informations. Then, It waits for the request from the client. And when it receives it, it sends an acknowledgment packet and the client is connected to the network with malicious configurations served from our program (the attacker).


# Enjoy 

