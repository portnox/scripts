########################################
# The following script collects Docker logs from all Portnox containers running on the Docker host it's executed on. Those log files are then automatically uploaded to Portnox for review by support
# The script should be executed on the Docker host running Portnox containers, such as the Local RADIUS, TACACS+, ZTNA, Unifi Agent, SiEM, etc.
# To execute the script run the commmand in its entirety: [sudo bash -c 'curl -O https://raw.githubusercontent.com/portnox/scripts/refs/heads/main/uploadportnoxdockerlogs.sh && chmod +x ./uploadportnoxdockerlogs.sh && ./uploadportnoxdockerlogs.sh']
# Be sure to copy everything between the quotes
# The script must be run under sudo and will error if it is not. This permission is needed to access the Docker logs
# When prompted enter your customer (organization) name so Support can easily identify your logs
# When prompted for the URL and token enter the full URL as provided by support
# The URL will be long and in the following format "https://{storageaccount}.blob.core.windows.net/{container}?skoid={signed object ID}&sktid={signedTenantId}&skt={Signed Key Start}ske={Signed Key Expiry}&sks={Signed Key Service}&skv={signedKeyVersion}&sv={Signed Versio}&spr={signed protocol}&st={signed start time}&se={Signed Expiry}&sp={signed permissions}&sig={signature}"
########################################

#!/usr/bin/env bash

set -euo pipefail

########################################
# Require sudo / root
########################################
if [[ "$EUID" -ne 0 ]]; then
    echo "❌ This script must be run with sudo to collect Docker logs."
    echo
    echo "Please re-run the script using:"
    echo "  sudo $0"
    exit 1
fi

echo "=== Collecting Portnox Docker Logs and Uploading to Azure Blob ==="

########################################
# Preconditions
########################################
command -v docker >/dev/null 2>&1 || { echo "❌ Docker is not installed"; exit 1; }
command -v tar    >/dev/null 2>&1 || { echo "❌ tar is required"; exit 1; }
command -v curl   >/dev/null 2>&1 || { echo "❌ curl is required"; exit 1; }

########################################
# Prompt for customer name
########################################
read -rp "Enter Customer Name: " CUSTOMER_NAME
[[ -z "$CUSTOMER_NAME" ]] && { echo "❌ Customer name cannot be empty"; exit 1; }

SAFE_CUSTOMER_NAME=$(echo "$CUSTOMER_NAME" | tr '[:space:]' '_' | tr -cd '[:alnum:]_-')

########################################
# Prompt for full Azure Blob URL (with SAS)
########################################
read -rp "Enter full Azure Blob URL (including SAS token): " FULL_BLOB_URL
[[ -z "$FULL_BLOB_URL" ]] && { echo "❌ Azure Blob URL cannot be empty"; exit 1; }

########################################
# Find matching containers
########################################
CONTAINERS=$(docker ps --format '{{.Names}}' | grep -i portnox || true)
[[ -z "$CONTAINERS" ]] && { echo "❌ No running containers found with 'portnox'"; exit 1; }

########################################
# Create working directories
########################################
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
BASE_DIR="portnox_logs_${TIMESTAMP}"
TGZ_FILE="${SAFE_CUSTOMER_NAME}_portnox_logs_${TIMESTAMP}.tgz"

mkdir -p "$BASE_DIR"

########################################
# Collect logs
########################################
echo "📄 Collecting Docker logs..."
for CONTAINER_NAME in $CONTAINERS; do
    mkdir -p "${BASE_DIR}/${CONTAINER_NAME}"
    docker logs "$CONTAINER_NAME" \
        > "${BASE_DIR}/${CONTAINER_NAME}/docker.log" 2>&1 \
        || echo "⚠️ Failed to collect logs for $CONTAINER_NAME"
done

########################################
# Create TGZ archive
########################################
echo "📦 Creating TGZ archive..."
tar -czf "$TGZ_FILE" "$BASE_DIR"

FILE_PATH="$(pwd)/$TGZ_FILE"
FILE_NAME=$(basename "$FILE_PATH")

########################################
# Cross-platform file size detection
########################################
if stat -c%s "$FILE_PATH" >/dev/null 2>&1; then
    FILE_SIZE=$(stat -c%s "$FILE_PATH")
else
    FILE_SIZE=$(stat -f%z "$FILE_PATH")
fi

########################################
# Build final Blob URL
########################################
BASE_URL="${FULL_BLOB_URL%%\?*}"
QUERY_STRING=""
if [[ "$FULL_BLOB_URL" == *"?"* ]]; then
    QUERY_STRING="?${FULL_BLOB_URL#*\?}"
fi

NORMALIZED_BASE=$(echo "$BASE_URL" | sed -E 's#(https://[^/]+)/+#\1/#; s#//+#/#g')
BLOB_URL="${NORMALIZED_BASE%/}/${FILE_NAME}${QUERY_STRING}"

########################################
# Output curl command
########################################
echo
echo "🔎 Upload command to be executed:"
echo
echo "curl -X PUT \"${BLOB_URL}\" \\"
echo "  -H \"x-ms-blob-type: BlockBlob\" \\"
echo "  -H \"Content-Length: ${FILE_SIZE}\" \\"
echo "  --data-binary \"@${FILE_PATH}\""
echo

########################################
# Execute upload
########################################
echo "📤 Uploading archive to Azure Blob Storage..."

set +e
HTTP_RESPONSE=$(curl -sS --http1.1 -w "%{http_code}" \
  -o /tmp/azure_upload_response.txt \
  -X PUT "$BLOB_URL" \
  -H "x-ms-blob-type: BlockBlob" \
  -H "Content-Length: $FILE_SIZE" \
  --data-binary @"$FILE_PATH")
CURL_EXIT_CODE=$?
set -e

########################################
# Result handling + cleanup
########################################
if [[ "$HTTP_RESPONSE" == "201" ]]; then
    echo
    echo "✅ Upload successful!"
    echo "📁 Uploaded archive: $FILE_NAME"

    if [[ "$CURL_EXIT_CODE" -ne 0 ]]; then
        echo "⚠️ curl exited with code $CURL_EXIT_CODE after successful upload (safe to ignore)"
    fi

    echo
    echo "🧹 Cleaning up temporary files..."
    rm -f "$TGZ_FILE"
    rm -rf "$BASE_DIR"

    echo "✔ Cleanup complete"
    exit 0
fi

########################################
# Failure path
########################################
echo
echo "❌ Upload failed"
echo "HTTP Status: $HTTP_RESPONSE"
echo "curl exit code: $CURL_EXIT_CODE"
echo
echo "Azure response:"
cat /tmp/azure_upload_response.txt
exit 1
