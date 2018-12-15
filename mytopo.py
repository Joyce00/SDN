# python 3.7.1
# windows 10
# encode -- UTF-8 --
# copyright (c) 2018 Joyce_BY at SYSU
# All rights reserved
# contact by email: Yagnes126@gmail.com

from mininet.topo import Topo

'''
h1---s1------s3---h3
      |\    /|\
      |  s5  | s6---h5
      |/   \ |/
h2---s2------s4---h4

'''

class mytopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        # add 5 hosts
        h1 = self.addHost('h1',ip='10.0.0.1/24')
        h2 = self.addHost('h2',ip='10.0.0.2/24')
        h3 = self.addHost('h3',ip='10.0.0.3/24')
        h4 = self.addHost('h4',ip='10.0.0.4/24')
        h5 = self.addHost('h5',ip='10.0.0.5/24')

        # add 6 switches
        s1 = self.addSwitch('s1',protocols = ['OpenFlow13'])
        s2 = self.addSwitch('s2',protocols = ['OpenFlow13'])
        s3 = self.addSwitch('s3',protocols = ['OpenFlow13'])
        s4 = self.addSwitch('s4',protocols = ['OpenFlow13'])
        s5 = self.addSwitch('s5',protocols = ['OpenFlow13'])
        s6 = self.addSwitch('s6',protocols = ['OpenFlow13'])

        # add links
        self.addLink(h5,s6,1,1)
        self.addLink(h1,s1,1,1)
        self.addLink(h2,s2,1,1)
        self.addLink(h3,s3,1,1)
        self.addLink(h4,s4,1,1)
        
        self.addLink(s1,s2,2,2)
        self.addLink(s1,s3,3,3)
        self.addLink(s1,s5,4,1)

        self.addLink(s4,s2,3,3)
        self.addLink(s4,s3,4,4)
        self.addLink(s4,s5,5,3)

        self.addLink(s5,s2,2,4)
        self.addLink(s5,s3,4,5)
        
        self.addLink(s6,s3,2,2)
        self.addLink(s6,s4,3,2)

topos = {'topo': (lambda:mytopo())}
