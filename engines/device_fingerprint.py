def get_device_type(ip_address, mac_address, gateway_ip=None, local_ip=None):

    mac_prefix = mac_address.upper()[0:8]

    # -----------------------------
    # Gateway detection
    # -----------------------------
    if gateway_ip and ip_address == gateway_ip:
        return "Gateway / Router"

    # -----------------------------
    # VirtualBox
    # -----------------------------
    if mac_prefix == "08:00:27":
        return "Virtual Machine (VirtualBox)"

    # VMware
    if mac_prefix == "00:0C:29":
        return "Virtual Machine (VMware)"

    # Raspberry Pi
    if mac_prefix == "B8:27:EB":
        return "Raspberry Pi"

    # Apple (generic range check)
    if mac_prefix in ["A4:5E:60", "F0:18:98", "DC:A6:32"]:
        return "Apple Device"

    # Samsung (common prefix examples)
    if mac_prefix in ["F4:F5:E8", "28:39:5E"]:
        return "Android Device (Samsung)"

    # -----------------------------
    # Local machine
    # -----------------------------
    if local_ip and ip_address == local_ip:
        return "Linux Host"

    # -----------------------------
    # Default fallback
    # -----------------------------
    return "Unknown Device"
