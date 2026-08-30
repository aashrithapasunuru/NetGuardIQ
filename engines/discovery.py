import socket
import ipaddress

from scapy.all import ARP, Ether, srp

from engines.device_inventory import save_device
from engines.timeline import add_timeline_event


HOSTNAME = socket.gethostname()


def get_local_network():
    """
    Returns the local IPv4 network in CIDR format.
    Example:
        192.168.1.9/24 -> 192.168.1.0/24
    """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # Doesn't actually contact Google.
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    network = ipaddress.ip_network(f"{ip}/24", strict=False)

    return str(network)


def arp_scan(network):

    print(f"[INFO] Scanning {network}")

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)

    answered = srp(
        packet,
        timeout=2,
        verbose=False
    )[0]

    return answered


def main():

    network = get_local_network()

    add_timeline_event(
        incident_id=1,
        event_type="DISC",
        attack_type="DISCOVERY",
        source="NetGuardIQ",
        severity="INFO",
        username="System",
        hostname=HOSTNAME,
        event="Network asset discovery started",
        details=f"Scanning network {network}"
    )

    answered = arp_scan(network)

    discovered = 0

    for _, received in answered:

        ip_address = received.psrc
        mac_address = received.hwsrc

        save_device(
            ip_address,
            mac_address
        )

        add_timeline_event(
            incident_id=1,
            event_type="DISC",
            attack_type="DISCOVERY",
            source="NetGuardIQ",
            severity="INFO",
            username="System",
            hostname=HOSTNAME,
            event="Device discovered",
            details=f"IP={ip_address}, MAC={mac_address}"
        )

        print("----------------------------------------")
        print("IP :", ip_address)
        print("MAC:", mac_address)

        discovered += 1

    add_timeline_event(
        incident_id=1,
        event_type="DISC",
        attack_type="DISCOVERY",
        source="NetGuardIQ",
        severity="INFO",
        username="System",
        hostname=HOSTNAME,
        event="Network asset discovery completed",
        details=f"Discovered {discovered} device(s)"
    )

    print(f"\n[INFO] Discovery Complete - {discovered} device(s) found")


if __name__ == "__main__":
    main()
