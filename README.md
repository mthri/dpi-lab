# DPI Laboratory Setup Guide

## 1. Virtual Environment Setup (VirtualBox)

### 1.1 VirtualBox Requirements

* VirtualBox 7.x or newer
* Host system with hardware virtualization enabled (VT-x / AMD-V)

### 1.2 Network Design Overview

The lab consists of two virtual machines:

* **Gateway Server VM**: Acts as router, DHCP server, and DPI enforcement point
* **Client VM(s)**: Traffic source, no direct internet access

Network types:

* **Bridged Adapter**: Internet-facing interface (Gateway VM only)
* **Internal Network**: Isolated lab network shared between Gateway and Clients

---

### 1.3 Gateway Server VM Configuration

**Operating System**: Ubuntu Server 24.04

**Network Adapters**:

1. Adapter 1

   * Type: Bridged Adapter
   * Purpose: Internet access
2. Adapter 2

   * Type: Internal Network
   * Name: `intnet`
   * Purpose: Client traffic

---

### 1.4 Client VM Configuration

**Operating System**: Ubuntu (Server or Desktop)

**Network Adapters**:

1. Adapter 1

   * Type: Internal Network
   * Name: `intnet`

Clients must not have any Bridged or NAT adapters.

---

### 1.5 IP Addressing Model

* Gateway (Internal Interface): `192.168.100.1/24`
* DHCP Range: `192.168.100.10 – 192.168.100.200`
* Default Gateway for Clients: `192.168.100.1`

---

## 2. Base Network Configuration Inside VMs

### 2.1 Gateway VM

* Enable IP forwarding
* Configure static IP on internal interface
* Install and configure DHCP server bound to internal interface
* Enable NAT (MASQUERADE) from internal interface to bridged interface

### 2.2 Client VMs

* Obtain IP configuration via DHCP
* Default route must point to Gateway VM
* No direct internet-facing interface

---

## 3. Gateway Server Configuration

### 3.1 Core Responsibilities

The Gateway VM acts as:

* Default gateway for all client traffic
* DHCP server for the internal network
* Traffic forwarding and control point

---

### 3.2 DHCP Server Setup

Install the DHCP server:

```
sudo apt update
sudo apt install -y isc-dhcp-server
```

Bind DHCP to the internal interface (example: `enp0s8`):

Edit `/etc/default/isc-dhcp-server`:

```
INTERFACESv4="enp0s8"
```

Configure the DHCP subnet:

Edit `/etc/dhcp/dhcpd.conf`:

```
subnet 192.168.100.0 netmask 255.255.255.0 {
  range 192.168.100.10 192.168.100.200;
  option routers 192.168.100.1;
  option domain-name-servers 8.8.8.8, 1.1.1.1;
}
```

Restart the service:

```
sudo systemctl restart isc-dhcp-server
```

---

### 3.3 IP Forwarding

Enable IPv4 forwarding temporarily:

```
sudo sysctl -w net.ipv4.ip_forward=1
```

Make it persistent:

Edit `/etc/sysctl.conf` and ensure:

```
net.ipv4.ip_forward=1
```

Apply changes:

```
sudo sysctl -p
```

---

### 3.4 NAT and Internet Access

Assumptions:

* Internal interface: `enp0s8`
* Internet-facing interface: `enp0s3`

Enable NAT:

```
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
```

Allow forwarding from internal to internet:

```
sudo iptables -A FORWARD -i enp0s8 -o enp0s3 -j ACCEPT
```

Allow return traffic:

```
sudo iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state ESTABLISHED,RELATED -j ACCEPT
```

---

### 3.5 Firewall Baseline

Ensure the default FORWARD policy is permissive:

```
sudo iptables -P FORWARD ACCEPT
```

(Recommended) Save iptables rules:

```
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

---

## 4. nDPI Installation (Gateway VM)

### 4.1 Build nDPI

```bash
git clone --branch dev https://github.com/ntop/nDPI.git
cd nDPI
./autogen.sh
./configure
make
sudo make install
```

---

### 4.2 Install nDPI Python Bindings

```bash
cd python
python3 -m pip install --upgrade pip
python3 -m pip install -r dev_requirements.txt
python3 -m pip install .
```

## 5. DPI Engine Setup and Activation

### 5.1 Clone DPI Lab Code

```bash
cd
git clone https://github.com/mthri/dpi-lab.git
cd dpi-lab
```

---

### 5.2 Install Python Dependencies

```bash
python3 -m pip install scapy==2.7.0 NetfilterQueue==1.1.0
```

---

### 5.3 Run the DPI Firewall

```bash
sudo python3 dpi_engine.py
```

The DPI process must run with root privileges to receive packets from NFQUEUE.

---

### 5.4 Redirect Traffic to User Space (NFQUEUE)

Forward all transit traffic to NFQUEUE:

```bash
sudo iptables -I FORWARD -j NFQUEUE --queue-num 3
```

Important:

* The queue number used in this command **must match** the queue number bound in the Python DPI code
* If the DPI process is not running, traffic handling depends on the firewall default policy

---
Sure! Here's a concise and professional text you can add at the end of your document:

---

## Additional Resources

I have recorded a comprehensive tutorial video in Persian (Farsi) covering this DPI lab setup and its usage. The video is available on both [YouTube](https://www.youtube.com/watch?v=zd0CjEYTvI8) and [Aparat](https://www.aparat.com/v/xqbrr74) platforms for your convenience.

Feel free to watch it to better understand the steps and concepts involved.
