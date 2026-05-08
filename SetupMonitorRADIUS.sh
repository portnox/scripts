# Use this script to setup and configure continous monitoring of local RADIUS via cron
# 'monitorRADIUS.sh' calls the standalone'localradfwtest.sh' script and logs its output to a 
# file adding the start and end date/timestamps. To execute copy and paste the following
# command into your local RADIUS or other Linux machine to execute.
# "curl -o SetupMonitorRADIUS.sh https://raw.githubusercontent.com/portnox/scripts/refs/heads/main/SetupMonitorRADIUS.sh && chmod +x SetupMonitorRADIUS.sh && ./SetupMonitorRADIUS.sh"

#Directory where scripts will be stored
SCRIPT_DIR="/opt/portnox"

# Create directory if it does not exist
mkdir -p "$SCRIPT_DIR"

# Download scripts
curl -fsSL https://raw.githubusercontent.com/portnox/scripts/refs/heads/main/localradfwtest.sh \
    -o "$SCRIPT_DIR/localradfwtest.sh"

curl -fsSL https://raw.githubusercontent.com/portnox/scripts/refs/heads/main/monitorRADIUS.sh \
    -o "$SCRIPT_DIR/monitorRADIUS.sh"

# Make scripts executable
chmod +x "$SCRIPT_DIR/localradfwtest.sh"
chmod +x "$SCRIPT_DIR/monitorRADIUS.sh"

# Add cron job to run monitorRADIUS.sh every minute
CRON_JOB="* * * * * $SCRIPT_DIR/monitorRADIUS.sh"

# Install cron job only if it does not already exist
(crontab -l 2>/dev/null | grep -F "$SCRIPT_DIR/monitorRADIUS.sh") >/dev/null || \
(
    crontab -l 2>/dev/null
    echo "$CRON_JOB"
) | crontab -

echo "Scripts downloaded and configured successfully."
echo "Cron job installed:"
echo "$CRON_JOB"
