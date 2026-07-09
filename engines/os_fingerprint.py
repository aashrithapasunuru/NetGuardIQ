import socket
import subprocess
import re
from mac_vendor_lookup import MacLookup

lookup = MacLookup()


def get_hostname(ip_address):
    """
    Resolve hostname from IP address.
    """

    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except Exception:
        return "Unknown"


def get_default_gateway():
    """
    Returns the default gateway IP.
    """

    try:
        output = subprocess.check_output(
            ["ip", "route"],
            text=True
        )

        for line in output.splitlines():
            if line.startswith("default"):
                return line.split()[2]

    except Exception:
        pass

    return None



def get_vendor(mac_address):
    """
    Returns the hardware vendor using the IEEE OUI database.
    """

    try:
        return lookup.lookup(mac_address)
    except Exception:
        return "Unknown"


def nmap_os_detection(ip_address):
    """
    Uses Nmap OS detection.
    """

    try:

        output = subprocess.check_output(
            [
                "nmap",
                "-O",
                "-Pn",
                "--host-timeout",
                "8s",
                ip_address
            ],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10
        )

    except Exception:
        return "Unknown"

    # Running: Microsoft Windows 11
    match = re.search(r"Running:\s*(.*)", output)

    if match:
        return match.group(1).strip()

    # Aggressive OS guesses: Linux 6.x (96%)
    match = re.search(r"Aggressive OS guesses:\s*(.*)", output)

    if match:
        guess = match.group(1)

        return guess.split(",")[0].strip()

    return "Unknown"


def determine_device_type(ip_address, hostname, vendor, operating_system):

    gateway = get_default_gateway()

    if ip_address == gateway:
        return "Default Gateway"

    host = hostname.lower()
    vendor = vendor.lower()
    os_name = operating_system.lower()

    if "kali" in host or "kali" in os_name:
        return "Security Workstation"

    if "ubuntu" in host or "ubuntu" in os_name:
        return "Monitoring Server"

    if "windows" in os_name:
        return "Windows Workstation"

    if "apple" in vendor:
        return "Apple Device"

    if "samsung" in vendor:
        return "Android Device"

    if "xiaomi" in vendor:
        return "Android Device"

    if "google" in vendor:
        return "Android Device"

    if "tp-link" in vendor:
        return "Router"

    if "cisco" in vendor:
        return "Network Device"

    if "oracle" in vendor:
        return "Virtual Machine"

    if "vmware" in vendor:
        return "Virtual Machine"

    if "linux" in os_name:
        return "Linux Device"

    return "Unknown"


def determine_criticality(device_type):
    """
    Assign default criticality.
    """

    mapping = {

        "Default Gateway": "Critical",

        "Monitoring Server": "Critical",

        "Security Workstation": "High",

        "Workstation": "Medium",

        "Linux Device": "Medium",

        "Router": "Critical",
        
        "Network Device": "High",

        "Android Device": "Low",

        "Apple Device": "Low",

        "virtual Machine": "Medium",

        "Unknown": "Medium"

    }

    return mapping.get(device_type, "Medium")


def fingerprint_device(ip_address, mac_address):
    """
    Main fingerprinting function.
    """

    hostname = get_hostname(ip_address)

    vendor = get_vendor(mac_address)

    operating_system = nmap_os_detection(ip_address)

    device_type = determine_device_type(
        ip_address,
        hostname,
        vendor,
        operating_system
    )

    criticality = determine_criticality(device_type)

    return {

        "hostname": hostname,

        "vendor": vendor,

        "operating_system": operating_system,

        "device_type": device_type,

        "criticality": criticality

    }


if __name__ == "__main__":

    ip = input("IP Address: ")

    mac = input("MAC Address: ")

    result = fingerprint_device(ip, mac)

    print("\nFingerprint Result")

    print("------------------------------")

    for key, value in result.items():

        print(f"{key:20}: {value}")
