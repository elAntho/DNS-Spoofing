# Laboratorio: DNS Spoofing & ARP Poisoning Attack 🎭

**Instituto Tecnológico de Las Américas (ITLA)**
* **Materia:** Seguridad de Redes
* **Profesor:** Jonathan Rondón
* **Estudiante:** Anthony De Los Santos
* **Matrícula:** 2025-1335

---

## 🎥 Video Demostrativo
▶️ **Enlace a YouTube:** https://youtu.be/hz3ean9QzIc 

*(El video incluye demostración con cámara, voz, fecha/hora, topología y comprobación de la herramienta).*

---

## 📄 Documentación Técnica

### Objetivo del Laboratorio
Demostrar de forma práctica la explotación de la confianza en redes locales (Capa 2/3) realizando un ataque Man-in-the-Middle que permita interceptar y manipular la resolución de nombres DNS.

### Objetivo del Script
Interceptar las solicitudes de resolución de nombres originadas por la máquina víctima dirigidas al dominio oficial `itla.edu.do`. El script responde de manera fraudulenta (Spoofing) inyectando la IP del atacante, redirigiendo a la víctima hacia un servicio web local controlado, apoyándose en un envenenamiento ARP previo.

### Parámetros Usados
* **ATTACKER_IP:** `10.25.133.12` (IP del servicio web falso).
* **VICTIM_IP:** Asignación dinámica DHCP de la máquina Windows 10/VPC.
* **GATEWAY_IP:** `10.25.133.1` (R1-Core).
* **TARGET_DOMAIN:** `itla.edu.do`.

### Requisitos para utilizar la herramienta
* Intérprete de Python 3 y librería Scapy.
* Activación de IP Forwarding en el atacante Linux (`sysctl -w net.ipv4.ip_forward=1`).
* Permisos de superusuario (root) para manipulación de `iptables`.

### Documentación del Funcionamiento
1. **Fase 1 (ARP Poisoning):** El script de envenenamiento resuelve las MACs y envía respuestas ARP gratuitas continuas. Le indica a la víctima que la MAC del Gateway es la del atacante.
2. **Fase 2 (Iptables):** Se bloquea el tráfico de reenvío en el puerto 53 UDP/TCP, asegurando que el servidor DNS real no pueda responder a la víctima antes que el atacante.
3. **Fase 3 (DNS Spoofing):** Scapy captura el tráfico DNS Query (`qr=0`) hacia `itla.edu.do` y fabrica al instante un paquete DNS Response (`qr=1`) autoritativo devolviendo la IP `10.25.133.12`.

### Topología y Direccionamiento
* **VLAN 133 (Usuarios/Atacante):** `10.25.133.0/24` (IP Atacante: 10.25.133.12).
* **Gateway:** `10.25.133.1`.

*(Ver documento PDF adjunto en este repositorio para capturas de pantalla de la topología y evidencia de ejecución).*

### Contramedidas (Mitigación)
* **Dynamic ARP Inspection (DAI):** Implementar DAI en el switch para validar paquetes ARP contra la tabla de DHCP Snooping.
* **DHCP Snooping:** Activar para crear una base de datos confiable de asignaciones IP/MAC.
* **DNSSEC:** Implementar extensiones de seguridad firmadas criptográficamente para validar la autenticidad de las resoluciones DNS.