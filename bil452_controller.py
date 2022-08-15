# ELE 466 Proje
# Seyyid Hikmet Celik
# 181201047

# QoS + Firewall Bulunan Sdn Controller Python Kodu

# En kısa yolu bulmak ve buna gore yonlendirme yapmak icin
import networkx as nx

# Firewall icin gerekli
import time
import threading

# pox icin gerekli kutuphaneler
from collections import Counter, defaultdict
from urllib.parse import quote_from_bytes

from pyrsistent import v
from requests import request
from pox.core import core
import pox.openflow.discovery
import pox.host_tracker
import pox.openflow.spanning_tree as spanning_tree
import pox.openflow.libopenflow_01 as of
import pox.lib.util as poxutil
from pox.lib.recoco import Timer
from pox.openflow.of_json import *

# q opsiyonunu alan flag
isQoS = False

# 1 saniyede gelen paket sayisini tutan degisken
reqcount = 0

# portlari durduran flag
stopport = False

# host adresleri
h1addr = '00:00:00:00:00:01'
h2addr = '00:00:00:00:00:02'
h3addr = '00:00:00:00:00:03'
h4addr = '00:00:00:00:00:04'
h5addr = '00:00:00:00:00:05'
h6addr = '00:00:00:00:00:06'
h7addr = '00:00:00:00:00:07'

# switch adresleri
s1addr = '00:00:00:00:00:11'
s2addr = '00:00:00:00:00:12'
s3addr = '00:00:00:00:00:13'
s4addr = '00:00:00:00:00:14'

# Baslangicta cagirilan sdn kontrolcu sinifi
class bil452_controller(object):
    def __init__(self):
        self.switch_links_to_port = {}
        self.paths_applied = {}
        self.spanning_tree = {}
        self.mac_to_port = {}
        self.topology = nx.Graph()
        self.loop = []

        # switch - mac adresleri tablosu
        self.table = {}

        self.ip_to_mac = {}
        self.traffic_pair_counter = Counter()

        self.all_ports = of.OFPP_FLOOD

        self.switches_bw = defaultdict(lambda: defaultdict(int))

        core.openflow.addListenerByName("PortStatsReceived", self._handle_portstats_received)
        core.openflow.addListenerByName("QueueStatsReceived", self._handle_qeuestats_received)
        
        core.openflow.addListenerByName("PacketIn", self._handle_PacketIn)
        core.openflow.addListenerByName("ConnectionUp", self._handle_ConnectionUp)
        core.openflow_discovery.addListenerByName("LinkEvent", self._handle_LinkEvent)  # listen to openflow_discovery
        core.host_tracker.addListenerByName("HostEvent", self._handle_HostEvent)  # listen to host_tracker

        # Firewall ayri threadde calisarak digerlerini bloklamiyor
        frwl = threading.Thread(target=self.firewall)
        frwl.start()

    def firewall(self):
        #print("FIREWALL")
        global reqcount
        global stopport

        # firewall kendi thread'inde surekli calisacak 
        # 1 saniye icinde 10'dan fazla paket olunca o zaman portu bloklayacak
        while True:
            # Bir saniye bekle o sırada paketler sayiliyor ve 10'dan fazla olursa firewall
            time.sleep(1)
            
            # Bu bir saniye icinde 10'dan fazla paket  geldiyse portu 10 saniyeligine durdur devam et
            if reqcount > 10:
                stopport = True
                print("FIREWALL!")
                for i in range(10,0,-1):
                    time.sleep(1)
                    print("FIREWALL CALISIYOR..." + i.__str__())

                print("FIREWALL BITTI!")
                #time.sleep(10)
                stopport = False

            # Yeni firewall icin guncelleme
            reqcount = 0

    # qeue stat'larini almak icin
    def _handle_qeuestats_received (self, event):
        stats = flow_stats_to_list(event.stats)

    # port stat'larini almak icin
    def _handle_portstats_received(self,event):
        for f in event.stats:
            if int(f.port_no)<65534: # used from hosts and switches interlinks
                current_bytes = f.rx_bytes + f.tx_bytes  # transmitted and received
                try:
                    last_bytes = self.switches_bw[int(event.connection.dpid)][int(f.port_no)]
                except:
                    last_bytes = 0
                estim_bw = (((current_bytes - last_bytes)/1024)/1024)*8
                estim_bw = float(format(estim_bw, '.2f'))
                #if estim_bw > 0:
                #    print(pox.lib.util.dpidToStr(event.connection.dpid), f.port_no, estim_bw)

                self.switches_bw[int(event.connection.dpid)][int(f.port_no)] = (f.rx_bytes + f.tx_bytes)

    # switch'lerden stat'lari almak icin
    def _timer_func (self):
        for connection in core.openflow._connections.values():
            connection.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
            connection.send(of.ofp_stats_request(body=of.ofp_queue_stats_request()))

    # Openflow switch baglantilarinda calisir
    def _handle_ConnectionUp(self, event):
        self.topology.add_node(pox.lib.util.dpid_to_str(event.dpid))
        Timer(1, self._timer_func, recurring=True)
        self.switches_bw[int(event.dpid)] = {}

    # Link event'leri dinler
    def _handle_LinkEvent(self, event):
        s1 = pox.lib.util.dpid_to_str(event.link.dpid1)
        s2 = pox.lib.util.dpid_to_str(event.link.dpid2)

        p1, p2 = event.link.port1, event.link.port2
        self.switch_links_to_port[s1, s2] = (p1, p2)

        lett = threading.Thread(target=self.link_event_to_topology, args=(s1, s2))
        lett.start()

    # Iki switch'i birbirine baglar 
    def link_event_to_topology(self, s1, s2):
        self.topology.add_edge(s1, s2, weight=100)
        try:
            self.loop = nx.cycle_basis(self.topology)[0]
            self.spanning_tree = spanning_tree._calc_spanning_tree()
        except:
            self.loop = []

    # Host tracker event'lerini dinler
    def _handle_HostEvent(self, event):
        macaddr = event.entry.macaddr.toStr()
        s = pox.lib.util.dpid_to_str(event.entry.dpid)
        self.mac_to_port[macaddr] = event.entry.port

        ahtt = threading.Thread(target=self.add_host_to_topology, args=(s, macaddr))
        ahtt.start()

    # Topolojiye host'lari ekler
    def add_host_to_topology(self, s, macaddr):
        self.topology.add_node(macaddr)
        self.topology.add_edge(s, macaddr, weight=10)

    # Paketleri dinler
    def _handle_PacketIn (self, event):
        packet = event.parsed

        # Kaynagi ogrenir
        self.table[(event.connection,packet.src)] = event.port
        if packet.type == packet.IPV6_TYPE:
            msg = of.ofp_packet_out()
            msg.buffer_id = None
            msg.in_port = event.port
            if not stopport:
                event.connection.send(msg)
            return

        if not packet.parsed:
            return
        if packet.type == 2048:
            pkt = packet.find('ipv4')
            self.ip_to_mac[pkt.srcip.toStr()] = packet.src
            self.ip_to_mac[pkt.dstip.toStr()] = packet.dst
            self.traffic_pair_counter[packet.src, packet.dst] += 1
        dst_port = self.table.get((event.connection, packet.dst))

        self.calculate_shortest_path(str(packet.src), str(packet.dst))

        if len(self.loop) > 0:
            if dst_port is None:
                msg = of.ofp_packet_out(data=event.ofp)

                tree_ports = [p[1] for p in self.spanning_tree.get(event.dpid, [])]
                
                for p in event.connection.ports:
                    if p >= of.OFPP_MAX:
                        continue

                    if not core.openflow_discovery.is_edge_port(event.dpid, p):
                        if p not in tree_ports:
                            continue

                    msg.actions.append(of.ofp_action_output(port=p))
                if not stopport:
                    event.connection.send(msg)
            else:
                msg = of.ofp_flow_mod()
                msg.match.dl_dst = packet.src
                msg.match.dl_src = packet.dst
                msg.priority = 1
                msg.hard_timeout = int(self.traffic_pair_counter[packet.dst, packet.src] * 2)
                msg.idle_timeout = int(self.traffic_pair_counter[packet.dst, packet.src])
                msg.actions.append(of.ofp_action_output(port=event.port))
                if not stopport:
                    event.connection.send(msg)

                msg = of.ofp_flow_mod()

                # Gelen paketi yonlendir
                msg.data = event.ofp
                msg.match.dl_src = packet.src
                msg.match.dl_dst = packet.dst
                msg.priority = 1
                msg.hard_timeout = int(self.traffic_pair_counter[packet.src, packet.dst] * 2)
                msg.idle_timeout = int(self.traffic_pair_counter[packet.src, packet.dst])
                msg.actions.append(of.ofp_action_output(port=dst_port))
                if not stopport:
                    event.connection.send(msg)
        else:
            if dst_port is None:
                msg = of.ofp_packet_out(data=event.ofp)
                msg.actions.append(of.ofp_action_output(port=self.all_ports))
                if not stopport:
                    event.connection.send(msg)
            else:
                msg = of.ofp_flow_mod()
                msg.match.dl_dst = packet.src
                msg.match.dl_src = packet.dst
                msg.priority = 1
                msg.hard_timeout = int(self.traffic_pair_counter[packet.dst, packet.src] * 2)
                msg.idle_timeout = int(self.traffic_pair_counter[packet.dst, packet.src])

                msg.actions.append(of.ofp_action_output(port=event.port))
                if not stopport:
                    event.connection.send(msg)

                msg = of.ofp_flow_mod()

                msg.data = event.ofp
                msg.match.dl_src = packet.src
                msg.match.dl_dst = packet.dst
                msg.priority = 1
                msg.hard_timeout = int(self.traffic_pair_counter[packet.src, packet.dst] * 2)
                msg.idle_timeout = int(self.traffic_pair_counter[packet.src, packet.dst])
                msg.actions.append(of.ofp_action_output(port=dst_port))
                if not stopport:
                    event.connection.send(msg)

    # Eger -q flagi gelirse yollari istenilen kurallara gore ayarlar
    def QoS(self, shortest_path):
        global h1addr, h2addr, h3addr, h4addr, h5addr, h6addr, h7addr, s1addr, s2addr, s3addr, s4addr
        qosed_path = []
        srcaddr = shortest_path[-1]
        dstaddr = shortest_path[0]
        # Eger h1 gonderiyorsa ve varacagi yer h1, h2, h3, h7 haric ise
        # h7 haric, diger paketler icin s4 uzerinden gecmeyecek kabul ettim
        if srcaddr == h1addr and len(shortest_path) > 4:
            if dstaddr == h4addr:
                qosed_path = [h4addr, s2addr, s1addr, h3addr]
            # s4 uzerinden gecmeyen s2 uzerinden gececek
            elif (dstaddr == h5addr or dstaddr == h6addr):
                qosed_path = shortest_path
                qosed_path[2] = s2addr

        # Eger h7 gonderiyorsa hepsinde s2'den gececek
        elif srcaddr == h7addr:
            if dstaddr == h1addr:
                qosed_path = [h1addr, s1addr, s2addr, s3addr, s4addr, h7addr]
            elif dstaddr == h2addr:
                qosed_path = [h2addr, s1addr, s2addr, s3addr, s4addr, h7addr]
            elif dstaddr == h3addr:
                qosed_path = [h3addr, s1addr, s2addr, s3addr, s4addr, h7addr]

            # h4'un pathini fixlemis oldum ama sorun degil, belirtilmemis
            elif dstaddr == h4addr:
                qosed_path = [h4addr, s2addr, s3addr, s4addr, h7addr]
            
            elif dstaddr == h5addr:
                qosed_path = [h5addr, s3addr, s2addr, s1addr, s4addr, h7addr]
            elif dstaddr == h6addr:
                qosed_path = [h6addr, s3addr, s2addr, s1addr, s4addr, h7addr]
            
        else:
            qosed_path = shortest_path

        return qosed_path

    # En kisa yolu networkx kutuphanesi ile bulup yonlendirmeyi buna gore yapiyorum
    # Eger -q flagi gelmis yani QoS varsa yollari istenilen kurallara gore degistiriyorum
    def calculate_shortest_path(self, source_mac, dst_mac):
        global isQoS
        global reqcount

        if source_mac in self.topology.nodes() and dst_mac in self.topology.nodes():
            shortest_path = nx.shortest_path(self.topology, source=source_mac, target=dst_mac)

            if isQoS:
                shortest_path = self.QoS(shortest_path)
            
            print("Paketin gectigi yol sayisi: " + len(shortest_path).__str__())
            print("Paketin gectigi yollar: " + list(reversed(shortest_path)).__str__())

            reqcount += 1
            
            if len(shortest_path)>2:
                self.shortest_path_flow_modifications(shortest_path)

    # En kisa yol hesaplandiktan sonra akis yonetimi burada yapilir
    def shortest_path_flow_modifications(self, shortest_path):
        source = shortest_path[0]
        target = shortest_path[-1]
        if not self.paths_applied.get((source,target)):
            switch_only = shortest_path[1:-1]

            for con in core.openflow._connections.values():
                if pox.lib.util.dpid_to_str(con.dpid) in switch_only:
                    switch_index = shortest_path.index(pox.lib.util.dpid_to_str(con.dpid))
                    ip_port_prev_datapath = shortest_path[switch_index-1]
                    ip_port_next_datapath = shortest_path[switch_index+1]

                    if ":" in ip_port_prev_datapath and ":" in ip_port_next_datapath:
                        in_port = self.mac_to_port.get(ip_port_prev_datapath)
                        out_port = self.mac_to_port.get(ip_port_next_datapath)
                        msg = of.ofp_flow_mod()
                        msg.match = of.ofp_match()
                        msg.match._in_port = in_port
                        msg.match.dl_src = EthAddr(source)
                        msg.match.dl_dst = EthAddr(target)
                        msg.priority = 100
                        msg.actions.append(of.ofp_action_output(port = out_port))
                        if not stopport:
                            con.send(msg)

                    if ":" in ip_port_prev_datapath and "-" in ip_port_next_datapath:
                        in_port = self.mac_to_port.get(ip_port_prev_datapath)
                        out_port = self.switch_links_to_port.get((pox.lib.util.dpid_to_str(con.dpid),ip_port_next_datapath))[0]
                        msg = of.ofp_flow_mod()
                        msg.match = of.ofp_match()
                        msg.match._in_port = in_port
                        msg.match.dl_src = EthAddr(source)
                        msg.match.dl_dst = EthAddr(target)
                        msg.priority = 100
                        msg.actions.append(of.ofp_action_output(port = out_port))
                        if not stopport:
                            con.send(msg)

                    if ":" in ip_port_next_datapath and "-" in ip_port_prev_datapath:
                        in_port = self.switch_links_to_port.get((pox.lib.util.dpid_to_str(con.dpid),ip_port_prev_datapath))[1]
                        out_port = self.mac_to_port.get(ip_port_next_datapath)
                        msg = of.ofp_flow_mod()
                        msg.match = of.ofp_match()
                        msg.match._in_port = in_port
                        msg.match.dl_src = EthAddr(source)
                        msg.match.dl_dst = EthAddr(target)
                        msg.priority = 100
                        msg.actions.append(of.ofp_action_output(port = out_port))
                        if not stopport:
                            con.send(msg)

                    if "-" in ip_port_next_datapath and "-" in ip_port_prev_datapath:
                        in_port = self.switch_links_to_port.get((ip_port_prev_datapath, pox.lib.util.dpid_to_str(con.dpid)))[1]
                        out_port = self.switch_links_to_port.get((pox.lib.util.dpid_to_str(con.dpid), ip_port_next_datapath))[0]
                        msg = of.ofp_flow_mod()
                        msg.match = of.ofp_match()
                        msg.match._in_port = in_port
                        msg.match.dl_src = EthAddr(source)
                        msg.match.dl_dst = EthAddr(target)
                        msg.priority = 100
                        msg.actions.append(of.ofp_action_output(port = out_port))
                        if not stopport:
                            con.send(msg)

                    self.paths_applied[(source,target)] = shortest_path
        # tersi
        shortest_path.reverse()
        source = shortest_path[0]
        target = shortest_path[-1]
        if not self.paths_applied.get((source,target)):
            switch_only = shortest_path[1:-1]

            for con in core.openflow._connections.values():
                if pox.lib.util.dpid_to_str(con.dpid) in switch_only:
                    switch_index = shortest_path.index(pox.lib.util.dpid_to_str(con.dpid))
                    ip_port_prev_datapath = shortest_path[switch_index-1]
                    ip_port_next_datapath = shortest_path[switch_index+1]

                    if ":" in ip_port_prev_datapath and ":" in ip_port_next_datapath:
                        in_port = self.mac_to_port.get(ip_port_prev_datapath)
                        out_port = self.mac_to_port.get(ip_port_next_datapath)
                        msg = of.ofp_flow_mod()
                        msg.match = of.ofp_match()
                        msg.match._in_port = in_port
                        msg.match.dl_src = EthAddr(source)
                        msg.match.dl_dst = EthAddr(target)
                        msg.priority = 100
                        msg.actions.append(of.ofp_action_output(port = out_port))
                        if not stopport:
                            con.send(msg)

                    if ":" in ip_port_prev_datapath and "-" in ip_port_next_datapath:
                        in_port = self.mac_to_port.get(ip_port_prev_datapath)
                        out_port = self.switch_links_to_port.get((pox.lib.util.dpid_to_str(con.dpid),ip_port_next_datapath))[0]
                        msg = of.ofp_flow_mod()
                        msg.match = of.ofp_match()
                        msg.match._in_port = in_port
                        msg.match.dl_src = EthAddr(source)
                        msg.match.dl_dst = EthAddr(target)
                        msg.priority = 100
                        msg.actions.append(of.ofp_action_output(port = out_port))
                        if not stopport:
                            con.send(msg)

                    if ":" in ip_port_next_datapath and "-" in ip_port_prev_datapath:
                        in_port = self.switch_links_to_port.get((pox.lib.util.dpid_to_str(con.dpid),ip_port_prev_datapath))[1]
                        out_port = self.mac_to_port.get(ip_port_next_datapath)
                        msg = of.ofp_flow_mod()
                        msg.match = of.ofp_match()
                        msg.match._in_port = in_port
                        msg.match.dl_src = EthAddr(source)
                        msg.match.dl_dst = EthAddr(target)
                        msg.priority = 100
                        msg.actions.append(of.ofp_action_output(port = out_port))
                        if not stopport:
                            con.send(msg)

                    if "-" in ip_port_next_datapath and "-" in ip_port_prev_datapath:
                        in_port = self.switch_links_to_port.get((ip_port_prev_datapath, pox.lib.util.dpid_to_str(con.dpid)))[1]
                        out_port = self.switch_links_to_port.get((pox.lib.util.dpid_to_str(con.dpid), ip_port_next_datapath))[0]
                        msg = of.ofp_flow_mod()
                        msg.match = of.ofp_match()
                        msg.match._in_port = in_port
                        msg.match.dl_src = EthAddr(source)
                        msg.match.dl_dst = EthAddr(target)
                        msg.priority = 100
                        msg.actions.append(of.ofp_action_output(port = out_port))
                        if not stopport:
                            con.send(msg)

                    self.paths_applied[(source,target)] = shortest_path

# QoS ve firewall iceren SDN kontrolcusunu kur
# ./pox.py forwarding.bil452_controller komutu ile baslatilabilir
# ./pox.py forwarding.bil452_controller -q komutu ile de QoS'lu hali baslatilabilir
def launch (q = False):
    # QoS icin q flagini burada komut ekranindan aliyorum ve global degiskene atiyorum ki yonlendirmede kullanabileyim
    global isQoS
    isQoS = q

    if isQoS:
        print("QoS SERVISI CALISIYOR...")
    else:
        print("QoS SERVISI KAPALI!")

    pox.openflow.discovery.launch()
    pox.host_tracker.launch()

    sdn_controller = bil452_controller()
    core.register(sdn_controller)
