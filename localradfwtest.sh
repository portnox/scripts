########################################
# The following script performs connectivity tests to verify all nessesary IPs and ports are accessible by the local RADIUS
# The scrit should be executed on the Docker host running the local RADIUS, or from within the Local RADIUS virtual appliance
########################################

#!/usr/bin/env bash
set -euo pipefail

########################################
# Configuration
########################################
BASE_PORT=443
EXTRA_PORTS=(80 5671 5672)

ALL_FQDNS=(
  "radius.portnox.com"
  "rad-events-clear-prod-eastus.servicebus.windows.net"
  "rad-events-clear-prod-westeu.servicebus.windows.net"
  "devices-ingress-clear-prod-eastus.servicebus.windows.net"
  "devices-ingress-clear-prod-westeu.servicebus.windows.net"
  "cloudcentraalstoreprodus.blob.core.windows.net"
  "cloudcentraalstoreprod.blob.core.windows.net"
  "pnxeusprdclrinstallers.blob.core.windows.net"
  "pnxweuprdclrinstallers.blob.core.windows.net"
  "logs-consolidation-prod-eastus.servicebus.windows.net"
  "logs-consolidation-prod-westeu.servicebus.windows.net"
  "portnox-centraal-prod.servicebus.windows.net"
  "portnox-centraal-prod-eastus.servicebus.windows.net"
)

EXTRA_PORT_FQDNS=(
  "portnox-centraal-prod.servicebus.windows.net"
  "portnox-centraal-prod-eastus.servicebus.windows.net"
)

########################################
# DNS Resolution (Service Bus–aware)
########################################
resolve_all_ips() {
  local fqdn="$1"

  local cname
  cname=$(dig +short CNAME "$fqdn" | sed 's/\.$//' | head -n1)

  if [[ -n "$cname" ]]; then
    if [[ "$cname" == *".privatelink."* ]]; then
      cname=$(dig +short CNAME "$cname" | sed 's/\.$//' | head -n1)
    fi
    dig +short A "$cname"
  else
    dig +short A "$fqdn"
  fi
}

########################################
# TCP Test
########################################
test_tcp() {
  local ip="$1"
  local port="$2"

  if timeout 3 bash -c "</dev/tcp/$ip/$port" &>/dev/null; then
    echo "PASS"
  else
    echo "FAIL"
  fi
}

########################################
# Helper: Extra ports?
########################################
needs_extra_ports() {
  local fqdn="$1"
  for extra in "${EXTRA_PORT_FQDNS[@]}"; do
    [[ "$fqdn" == "$extra" ]] && return 0
  done
  return 1
}

########################################
# Execute Tests (Wide Output)
########################################
echo
echo "Outbound Connectivity Test"
echo "=========================="
echo

for fqdn in "${ALL_FQDNS[@]}"; do
  IPS=$(resolve_all_ips "$fqdn" | sort -u)

  for ip in $IPS; do
    # Always test 443
    result=$(test_tcp "$ip" "$BASE_PORT")
    printf "Testing %-55s TCP %-5s ... %s\n" "$ip" "$BASE_PORT" "$result"

    # Conditionally test extra ports
    if needs_extra_ports "$fqdn"; then
      for port in "${EXTRA_PORTS[@]}"; do
        result=$(test_tcp "$ip" "$port")
        printf "Testing %-55s TCP %-5s ... %s\n" "$ip" "$port" "$result"
      done
    fi
  done
done

echo
echo "Connectivity test complete."
