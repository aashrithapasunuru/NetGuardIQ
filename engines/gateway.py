import subprocess

output = subprocess.check_output("ip route", shell=True).decode(errors="ignore")

for line in output.splitlines():
    if line.startswith("default"):
        gateway_ip = line.split()[2]
        print("Gateway IP:", gateway_ip)

print(output)
