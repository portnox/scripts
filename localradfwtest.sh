########################################
# The following script performs connectivity tests to verify all nessesary IPs and ports are accessible by the local RADIUS
# The scrit should be executed on the Docker host running the local RADIUS, or from within the Local RADIUS virtual appliance
# Download this script to the Linux machine using wget OR curl using the folowing examples: 
# - "wget https://raw.githubusercontent.com/portnox/scripts/refs/heads/main/localradfwtest.sh && chmod +x localradfwtest.sh && ./localradfwtest.sh" 
# - "curl -o localradfwtest.sh https://raw.githubusercontent.com/portnox/scripts/refs/heads/main/localradfwtest.sh && chmod +x localradfwtest.sh && ./localradfwtest.sh"
# Be sure to copy the entire command from the open quote to the close quote to make the script executable and launch the script
########################################
#!/bin/sh

# ==============================
# Configuration
# ==============================

TIMEOUT=3
FAILED=0

# Standard 443-only destinations
DEST_443="
radius.portnox.com
rad-events-clear-prod-eastus.servicebus.windows.net
rad-events-clear-prod-westeu.servicebus.windows.net
cloudcentraalstoreprodus.blob.core.windows.net
cloudcentraalstoreprod.blob.core.windows.net
pnxeusprdclrinstallers.blob.core.windows.net
pnxweuprdclrinstallers.blob.core.windows.net
logs-consolidation-prod-eastus.servicebus.windows.net
logs-consolidation-prod-westeu.servicebus.windows.net
"

# Service Bus namespaces requiring additional ports
SERVICEBUS_MULTI_PORT="
portnox-centraal-prod.servicebus.windows.net
portnox-centraal-prod-eastus.servicebus.windows.net
"

# ==============================
# TCP test function
# ==============================

tcp_test() {
  host="$1"
  port="$2"

  if command -v bash >/dev/null 2>&1; then
    bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
  elif command -v nc >/dev/null 2>&1; then
    nc -w "$TIMEOUT" -z "$host" "$port" >/dev/null 2>&1
  else
    return 1
  fi
}

# ==============================
# DNS resolution (portable)
# ==============================

resolve_all_names() {
  name="$1"

  # Always test the FQDN itself
  echo "$name"

  if command -v dig >/dev/null 2>&1; then
    dig +short "$name" A

  elif command -v host >/dev/null 2>&1; then
    host "$name" | awk '/has address/ {print $4}'

  elif command -v nslookup >/dev/null 2>&1; then
    nslookup "$name" 2>/dev/null | awk '
      /^Name:/ { seen=1; next }
      seen && /^Address [0-9]*:/ {
        ip=$3
        if (ip !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/)
          print ip
      }
    '
  fi
}

# ==============================
# Pretty output
# ==============================

print_result() {
  target="$1"
  port="$2"
  result="$3"

  printf "Testing %-60s TCP %-5s ... %s\n" "$target" "$port" "$result"
}

# ==============================
# Header
# ==============================

echo "Outbound Connectivity Test"
echo "=========================="
echo

# ==============================
# 443-only tests
# ==============================

for fqdn in $DEST_443; do
  for target in $(resolve_all_names "$fqdn"); do
    if tcp_test "$target" 443; then
      print_result "$target" 443 "PASS"
    else
      print_result "$target" 443 "FAIL"
      FAILED=1
    fi
  done
done

# ==============================
# Multi-port Service Bus tests
# ==============================

for fqdn in $SERVICEBUS_MULTI_PORT; do
  for target in $(resolve_all_names "$fqdn"); do
    for port in 443 80 5671 5672; do
      if tcp_test "$target" "$port"; then
        print_result "$target" "$port" "PASS"
      else
        print_result "$target" "$port" "FAIL"
        FAILED=1
      fi
    done
  done
done

# ==============================
# Final result
# ==============================

echo
if [ "$FAILED" -eq 0 ]; then
  echo "RESULT: ALL CONNECTIVITY TESTS PASSED"
  exit 0
else
  echo "RESULT: ONE OR MORE CONNECTIVITY TESTS FAILED"
  exit 1
fi
