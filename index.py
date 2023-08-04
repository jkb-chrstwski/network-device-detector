from scapy.all import ARP, Ether, srp
import netifaces as ni
import time
import logging
import os


def setup_logging():
    log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device_log.txt")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename=log_file,
        filemode="a"
    )

def get_arp_table(subnet):
    arp_request = ARP(pdst=subnet)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether / arp_request
    result = srp(packet, timeout=3, verbose=False)[0]
    arp_table = {}
    for _, rcv in result:
        arp_table[rcv[ARP].psrc] = rcv[Ether].src

    return arp_table


def detect_new_devices():
    existing_devices = set()
    ip_address = ni.ifaddresses(ni.gateways()['default'][ni.AF_INET][1])[
        ni.AF_INET][0]['addr']
    subnet = get_subnet_from_ip(ip_address)

    while True:
        arp_table = get_arp_table(subnet)

        for ip, mac in arp_table.items():
            if ip not in existing_devices:                
                print(f"New device connected: IP {ip}, MAC {mac}")
                logging.info(f"New device connected: IP {ip}, MAC {mac}")
                
                existing_devices.add(ip)

        time.sleep(5)


    

def get_subnet_from_ip(ip_address):
    interface = ni.gateways()['default'][ni.AF_INET][1]
    if_details = ni.ifaddresses(interface)[ni.AF_INET][0]

    subnet_mask = if_details['netmask']
    subnet_bits = sum(bin(int(x)).count('1') for x in subnet_mask.split('.'))
    subnet = f"{ip_address}/{subnet_bits}"

    return subnet





if __name__ == "__main__":
    setup_logging() 
    detect_new_devices()
