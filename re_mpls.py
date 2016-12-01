#!/usr/bin/python

"""
Script used for the Research Exercise
"""
import time
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info
# We use the OVSSwitch to handle OFP v1.2 or higher
# We import RemoteController class to use the RYU controller
from mininet.node import OVSSwitch, RemoteController



net = None

def run():
    # Creating the network according to Fig1. of PDF
    info( 'Creating the network' )
    net = Mininet( controller=RemoteController, switch=OVSSwitch ) # Controller

    info( '*** Adding controller\n' )
    # Without any additional parameters, by default Mininet will look into 127.0.0.1:6633 for the controller
    # This is consistent with RYU controller's default settings
    c0 = RemoteController('c0')
    net.addController(c0)

    info( '*** Adding hosts, switches and host-switch links\n' )
    switches = []
    for h in range(4):
        n = h + 1
        # We assign distinguishable dpid (datapath ID) to each switch for easy management
        switch = net.addSwitch('SW%s' % n, dpid='0%s0%s1ca21ab40%s0%s' % (n, n, n, n), protocols='OpenFlow13', datapath='user' )
        switches.append(switch)
        messg = 'Adding switch %s\n' % switches[h]
        info(messg)
        # We assigned distinguishable mac-addresses to each host
        if n % 2 == 0:
            host = net.addHost( 'h%s' % n, ip='10.10.1.%s/24' % (n-1), mac='1c:a2:1a:b4:00:0%s' % n )
            messg = 'Adding host %s\n' % host.name
            info(messg)
            net.addLink(switch, host)
        else:
            host = net.addHost( 'h%s' % n, ip='10.10.1.%s/24' % n, mac='1c:a2:1a:b4:01:0%s' % n )
            messg = 'Adding host %s\n' % host.name
            info(messg)
            net.addLink(switch, host)
        continue
    
    info( '*** Adding additional switches\n' )
    for h in range(5, 9):
        # We assigned distinguishable dpid (datapath ID) to each switch for easy management  mac='%s0:%s1:1c:a2:1a:b4'
        switch = net.addSwitch('SW%s' % h, dpid='0%s0%s1ca21ab40%s0%s' % (h, h, h, h), protocols='OpenFlow13', datapath='user' )
        switches.append(switch)
        messg = 'Adding switch %s\n' % switches[h-1]
        info(messg)
    
    info( '*** Creating Additional Links\n' )
    # We match Fig. 1 of PDF
    # Connections on SW1
    net.addLink( switches[0], switches[4])
    net.addLink( switches[0], switches[6])
    # Connections on SW3
    net.addLink( switches[2], switches[7])
    net.addLink( switches[2], switches[5])
    # Connections on SW2
    net.addLink( switches[1], switches[4])
    net.addLink( switches[1], switches[5])
    # Connections on SW4
    net.addLink( switches[3], switches[7])
    net.addLink( switches[3], switches[6])
    # Creating the Core mesh
    net.addLink( switches[4], switches[6]) #SW5, SW7
    net.addLink( switches[5], switches[7]) #SW6, SW8
    net.addLink( switches[4], switches[5]) #SW5, SW6
    net.addLink( switches[6], switches[7]) #SW7, SW8
    net.addLink( switches[4], switches[7]) #SW5, SW8
    net.addLink( switches[5], switches[6]) #SW6, SW7


    info( '*** Starting network\n')
    net.start()

    info( '*** Running CLI\n' )
    CLI( net )
    
    info( '*** Stopping network' )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()

