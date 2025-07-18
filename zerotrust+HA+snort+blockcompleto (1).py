# ha_zerotrust_snort.py - SDN Controller con Zero Trust, HA, monitoreo Snort y bloqueo reactivo
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
import requests, threading, time, json
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---------- Receptor HTTP de alertas enviadas desde Snort ----------
class SnortAlertHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        body = self.rfile.read(length)
        data = json.loads(body.decode('utf-8'))
        ip = data.get("src_ip")
        if ip:
            UnifiedZeroTrustPolicy.register_alert(ip)
            print(f"\n🔔 Alerta de Snort: {ip} → bloqueo de subred activado")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

# ---------- Clase principal del controlador SDN ----------
class UnifiedZeroTrustPolicy(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    bloqueos = {}  # { ip: {subredes bloqueadas} }

    @classmethod
    def register_alert(cls, src_ip):
        subredes = {
            "192.168.10.100": ["10.10.10.0/30", "10.10.20.0/30", "192.168.20.0/24", "192.168.40.0/24"],
            "192.168.20.100": ["10.10.10.0/30", "10.10.20.0/30", "192.168.10.0/24", "192.168.30.0/24", "1                                                           92.168.40.0/24"]
        }
        if src_ip in subredes:
            if src_ip not in cls.bloqueos:
                cls.bloqueos[src_ip] = set()
            for red in subredes[src_ip]:
                if red not in cls.bloqueos[src_ip]:
                    cls.bloqueos[src_ip].add(red)
                    for dp in cls._global_instance.datapaths:
                        cls._global_instance.bloquear(dp, src_ip, red)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        UnifiedZeroTrustPolicy._global_instance = self
        self.servers = ["192.168.30.101", "192.168.30.102"]
        self.virtual_ip = "192.168.30.117"
        self.best_server = self.servers[0]
        self.lock = threading.Lock()
        self.datapaths = []
        threading.Thread(target=self.ha_monitor, daemon=True).start()
        threading.Thread(target=self.api_snort, daemon=True).start()

    # ---------- Balanceo por carga ----------
    def ha_monitor(self):
        while True:
            best = min(self.servers, key=self.get_load)
            with self.lock:
                if best != self.best_server:
                    self.logger.info("[HA] Cambio de mejor servidor: %s (carga: %.1f)", best, self.get_lo                                                           ad(best))
                    self.best_server = best
                    for dp in self.datapaths:
                        self.flujos_http(dp)
            time.sleep(3)

    def get_load(self, ip):
        try:
            r = requests.get(f"http://{ip}:5000/status", timeout=2)
            d = r.json()
            return d.get("cpu", 100) + d.get("ram", 100)
        except:
            return float('inf')

    # ---------- HTTP listener para alertas ----------
    def api_snort(self):
        HTTPServer(('', 5001), SnortAlertHandler).serve_forever()

    def add_flow(self, dp, prio, match, actions):
        p = dp.ofproto_parser
        o = dp.ofproto
        inst = [p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=prio, match=match, instructions=inst))

    def bloquear(self, dp, ip, red):
        p = dp.ofproto_parser
        match = p.OFPMatch(eth_type=0x0800, ipv4_src=ip, ipv4_dst=(red))
        self.add_flow(dp, 450, match, [])
        print(f"📅 SDN: bloqueo reactivo aplicado a {ip} → {red}")

    def flujos_http(self, dp):
        p = dp.ofproto_parser
        o = dp.ofproto
        self.delete_http(dp)
        for ip in ["192.168.10.100", "192.168.20.100"]:
            self.logger.info(f"[HA] Cliente {ip} redirigido a {self.best_server}")
            match = p.OFPMatch(eth_type=0x0800, ip_proto=6,
                               ipv4_src=ip, ipv4_dst=self.virtual_ip, tcp_dst=80)
            actions = [p.OFPActionSetField(ipv4_dst=self.best_server)]
            if ip == "192.168.10.100":
                actions += [p.OFPActionOutput(o.OFPP_NORMAL)]
            if ip == "192.168.20.100":  # 🟡 Duplicar HTTP sospechoso hacia Snort
                actions += [p.OFPActionOutput(4)]  # puerto hacia snort
            self.add_flow(dp, 300, match, actions)

            # Respuesta WebServer → Cliente
            self.add_flow(dp, 300, p.OFPMatch(eth_type=0x0800, ip_proto=6,
                                              ipv4_src=self.best_server, ipv4_dst=ip, tcp_src=80),
                          [p.OFPActionSetField(ipv4_src=self.virtual_ip), p.OFPActionOutput(o.OFPP_NORMAL                                                           )])

    def delete_http(self, dp):
        p = dp.ofproto_parser
        o = dp.ofproto
        for ip in ["192.168.10.100", "192.168.20.100"]:
            for m in [
                p.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip, ipv4_dst=self.virtual_ip, tcp_dst=80                                                           ),
                p.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=self.best_server, ipv4_dst=ip, tcp_src=8                                                           0)
            ]:
                dp.send_msg(p.OFPFlowMod(datapath=dp, command=o.OFPFC_DELETE,
                    out_port=o.OFPP_ANY, out_group=o.OFPG_ANY, match=m))

    def duplicar_snort(self, dp, p, o):
        for h in ["192.168.10.100", "192.168.20.100"]:
            self.add_flow(dp, 210, p.OFPMatch(eth_type=0x0800, ipv4_src=h),
                          [p.OFPActionOutput(o.OFPP_NORMAL), p.OFPActionOutput(4)])
            self.add_flow(dp, 210, p.OFPMatch(eth_type=0x0800, ipv4_dst=h),
                          [p.OFPActionOutput(o.OFPP_NORMAL), p.OFPActionOutput(4)])

    def permitir_snort_sdn(self, dp, p, o):
        self.add_flow(dp, 220, p.OFPMatch(eth_type=0x0800, ip_proto=6,
            ipv4_src="192.168.40.100", ipv4_dst="192.168.40.1", tcp_dst=5001),
            [p.OFPActionOutput(o.OFPP_NORMAL)])
        self.add_flow(dp, 220, p.OFPMatch(eth_type=0x0800, ip_proto=6,
            ipv4_src="192.168.40.1", ipv4_dst="192.168.40.100", tcp_src=5001),
            [p.OFPActionOutput(o.OFPP_NORMAL)])

    def dns_http_https(self, dp, p, o, ip):
        self.add_flow(dp, 200, p.OFPMatch(eth_type=0x0800, ip_proto=17,
            ipv4_src=ip, udp_dst=53), [p.OFPActionOutput(o.OFPP_NORMAL)])
        self.add_flow(dp, 200, p.OFPMatch(eth_type=0x0800, ip_proto=17,
            ipv4_dst=ip, udp_src=53), [p.OFPActionOutput(o.OFPP_NORMAL)])
        for port in [80, 443]:
            self.add_flow(dp, 180, p.OFPMatch(eth_type=0x0800, ip_proto=6,
                ipv4_src=ip, tcp_dst=port), [p.OFPActionOutput(o.OFPP_NORMAL)])
            self.add_flow(dp, 180, p.OFPMatch(eth_type=0x0800, ip_proto=6,
                ipv4_dst=ip, tcp_src=port), [p.OFPActionOutput(o.OFPP_NORMAL)])

    def icmp(self, dp, p, o, src, dst):
        self.add_flow(dp, 200, p.OFPMatch(eth_type=0x0800, ip_proto=1,
            ipv4_src=src, ipv4_dst=dst), [p.OFPActionOutput(o.OFPP_NORMAL)])
        self.add_flow(dp, 200, p.OFPMatch(eth_type=0x0800, ip_proto=1,
            ipv4_src=dst, ipv4_dst=src), [p.OFPActionOutput(o.OFPP_NORMAL)])

    def arp(self, dp, p, o):
        self.add_flow(dp, 100, p.OFPMatch(eth_type=0x0806), [p.OFPActionOutput(o.OFPP_FLOOD)])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp, p, o = ev.msg.datapath, ev.msg.datapath.ofproto_parser, ev.msg.datapath.ofproto
        if dp not in self.datapaths:
            self.datapaths.append(dp)

        self.arp(dp, p, o)

        for h, g in [("192.168.10.100", "192.168.10.1"), ("192.168.20.100", "192.168.20.1")]:
            self.icmp(dp, p, o, h, g)
            self.dns_http_https(dp, p, o, h)

        for srv in self.servers:
            self.icmp(dp, p, o, "192.168.10.100", srv)
            self.icmp(dp, p, o, "192.168.30.1", srv)
            self.add_flow(dp, 210, p.OFPMatch(eth_type=0x0800, ip_proto=6,
                ipv4_src="192.168.30.1", ipv4_dst=srv, tcp_dst=5000), [p.OFPActionOutput(o.OFPP_NORMAL)])
            self.add_flow(dp, 210, p.OFPMatch(eth_type=0x0800, ip_proto=6,
                ipv4_src=srv, ipv4_dst="192.168.30.1", tcp_src=5000), [p.OFPActionOutput(o.OFPP_NORMAL)])

        self.flujos_http(dp)
        self.duplicar_snort(dp, p, o)
        self.permitir_snort_sdn(dp, p, o)
        self.add_flow(dp, 0, p.OFPMatch(), [])
        print("[SDN] Políticas de Zero Trust, HA y bloqueo reactivo aplicadas.")
