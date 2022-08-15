# ELE 466 Proje
# Seyyid Hikmet Celik
# 181201047

# Istenen ag topolojisinin tanimlandigi python kodu 

from mininet.topo import Topo

class bil452_topo(Topo):
    def build(self):
        # hostlari, mac ve ip adreslerini ekliyorum
        h1 = self.addHost('h1', mac = '00:00:00:00:00:01', ip='10.0.0.1')
        h2 = self.addHost('h2', mac = '00:00:00:00:00:02', ip='10.0.0.2')
        h3 = self.addHost('h3', mac = '00:00:00:00:00:03', ip='10.0.0.3')
        h4 = self.addHost('h4', mac = '00:00:00:00:00:04', ip='10.0.0.4')
        h5 = self.addHost('h5', mac = '00:00:00:00:00:05', ip='10.0.0.5')
        h6 = self.addHost('h6', mac = '00:00:00:00:00:06', ip='10.0.0.6')
        h7 = self.addHost('h7', mac = '00:00:00:00:00:07', ip='10.0.0.7')

        # switchleri ve datapath id'lerini (aslinda mac) ekliyorum
        s1 = self.addSwitch('s1', dpid='0000000000000011')
        s2 = self.addSwitch('s2', dpid='0000000000000012')
        s3 = self.addSwitch('s3', dpid='0000000000000013')
        s4 = self.addSwitch('s4', dpid='0000000000000014')

        # Verilen topolojiye gore linkleri ekliyorum 
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        
        self.addLink(h4, s2)
        
        self.addLink(h5, s3)
        self.addLink(h6, s3)
        
        self.addLink(h7, s4)
        
        self.addLink(s1, s2)
        self.addLink(s1, s4)
        
        self.addLink(s2, s3)
        
        self.addLink(s3, s4)
        

topos = { 'bil452_topo': ( lambda: bil452_topo() ) }
