Simple program to allow a user to check 802.3ad parameters of a link.

The idea is that this is used for a framwork for developing a monitoring
application that could notify another dataplane application that slave
parameters have changed.

Right now this simply prints a few 802.3ad parameters as an example.

```
$ ./ff p1p1
p1p1: up
ad_aggregator_id: 7
ad_actor_oper_port_state: 69
ad_partner_oper_port_state: 1
$ ./ff p1p2
p1p2: up
ad_aggregator_id: 5
ad_actor_oper_port_state: 77
ad_partner_oper_port_state: 1
```

