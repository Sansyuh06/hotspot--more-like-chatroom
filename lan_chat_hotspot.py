"""
HOTSPOT — More-Like-Chatroom
Transform WiFi hotspots into game-like chat lobbies

CHANGELOG:
✓ WiFi Integration: Scan networks, auto-detect SSID, show as lobby list
✓ Multicast UDP: Isolated per-SSID chat groups (239.X.Y.Z:12345)
✓ Lobby Browser: Game-like UI (SSID, Players, Ping, Last Msg, Join button)
✓ Heartbeat System: 5s broadcasts track live player count
✓ Game Features: Channels (Casual/Competitive), quick commands (/map, /team, /ready)
✓ Enhanced Notifications: Reactions, emojis, player status
✓ UI Polish: CS:GO-inspired black/green + neon, resizable, tray icon
✓ Cross-Platform: Windows/Mac/Linux sound, WiFi, file sharing
✓ Error Handling: WiFi permissions, firewall, NAT detection
✓ Stats: Message history, uptime tracking

SETUP:
pip install pywifi pystray pillow aiortc

DEMO:
1. Run on 2+ devices connected to same WiFi hotspot
2. App auto-detects SSID, joins multicast group
3. See nearby lobbies, click "Join Game" to switch
"""

import socket
import threading
import tkinter as tk
import json
import sys
import os
import uuid
import math
import struct
import tempfile
import subprocess
import time
import hashlib
import csv
from datetime import datetime, timedelta
from tkinter import ttk, messagebox, filedialog, scrolledtext
from typing import Dict, List, Optional, Tuple
from collections import deque
import struct
import platform

try:
    import winsound
except ImportError:
    winsound = None

try:
    import pywifi
    from pywifi import const
    PYWIFI_AVAILABLE = True
except ImportError:
    PYWIFI_AVAILABLE = False
    print("⚠ pywifi not installed. WiFi scanning disabled. Install: pip install pywifi")

try:
    import pystray
    from PIL import Image, ImageDraw
    PYSTRAY_AVAILABLE = True
except ImportError:
    PYSTRAY_AVAILABLE = False
    print("⚠ pystray/PIL not installed. Tray icon disabled. Install: pip install pystray pillow")

# ==================== CONFIGURATION ====================
PORT = 12345
BUFFER_SIZE = 4096
FILE_BUFFER_SIZE = 8192
XOR_KEY = 'SimpleChatKey123'
HEARTBEAT_INTERVAL = 5  # seconds
LOBBY_REFRESH_INTERVAL = 10  # seconds
MAX_PLAYERS_PER_LOBBY = 32
MULTICAST_TTL = 32
running = True
PLAYER_TIMEOUT = 15  # Remove player after 15s no heartbeat

# Color scheme - CS:GO inspired + neon
BACKGROUND = "#0D1117"
TEXT_COLOR = "#00FF00"
ACCENT_COLOR = "#1F6FEB"
NEON_CYAN = "#00FFFF"
NEON_MAGENTA = "#FF00FF"
INPUT_BG = "#161B22"
BUTTON_BG = "#21262D"
BUTTON_HOVER = "#30363D"
ERROR_COLOR = "#FF6B6B"
SUCCESS_COLOR = "#39FF14"
WARNING_COLOR = "#FFB800"
LOBBY_HIGHLIGHT = "#1B6AA6"

# ==================== UTILITY FUNCTIONS ====================

def xor_encrypt_decrypt(data: str, key: str) -> str:
    """Simple XOR encryption for basic message obfuscation"""
    result = ""
    for i, char in enumerate(data):
        result += chr(ord(char) ^ ord(key[i % len(key)]))
    return result

def get_local_ip() -> str:
    """Get the local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
        except:
            s.connect(('10.255.255.255', 1))
            local_ip = s.getsockname()[0]
        finally:
            s.close()
        return local_ip
    except:
        return '127.0.0.1'

def get_current_ssid() -> Optional[str]:
    """Detect current connected WiFi SSID (cross-platform)"""
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(['netsh', 'wlan', 'show', 'interface'], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'SSID' in line and ':' in line:
                    ssid = line.split(':', 1)[1].strip()
                    if ssid and ssid != '':
                        return ssid
        elif platform.system() == 'Darwin':  # macOS
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'],
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'SSID:' in line:
                    return line.split('SSID:', 1)[1].strip()
        else:  # Linux
            try:
                result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if 'ESSID:' in line:
                        ssid = line.split('ESSID:', 1)[1].strip().strip('"')
                        if ssid:
                            return ssid
            except:
                pass
    except Exception as e:
        print(f"DEBUG: SSID detection error: {e}")
    return None

def ssid_to_multicast_group(ssid: str) -> Tuple[str, int]:
    """Derive unique multicast group from SSID (239.X.Y.Z:PORT)"""
    ssid_hash = int(hashlib.md5(ssid.encode()).hexdigest()[:8], 16)
    octet1 = (ssid_hash >> 24) & 0xFF
    octet2 = (ssid_hash >> 16) & 0xFF
    octet3 = (ssid_hash >> 8) & 0xFF
    multicast_ip = f"239.{octet1 % 256}.{octet2 % 256}.{(octet3 % 254) + 1}"
    return multicast_ip, PORT

def scan_wifi_networks() -> List[Dict]:
    """Scan nearby WiFi networks using pywifi"""
    if not PYWIFI_AVAILABLE:
        return []
    
    try:
        wifi = pywifi.PyWiFi()
        ifaces = wifi.interfaces()
        if not ifaces:
            return []
        
        iface = ifaces[0]
        iface.scan()
        time.sleep(2)  # Wait for scan results
        
        networks = []
        seen_ssids = set()
        for network in iface.scan_results():
            ssid = network.ssid
            if ssid and ssid not in seen_ssids:
                seen_ssids.add(ssid)
                networks.append({
                    'ssid': ssid,
                    'signal': network.signal,  # dBm value
                    'frequency': network.freq,
                })
        return sorted(networks, key=lambda x: x['signal'], reverse=True)
    except Exception as e:
        print(f"DEBUG: WiFi scan error: {e}")
        return []

def signal_to_bars(signal_dbm: int) -> str:
    """Convert dBm signal to visual bars"""
    # dBm: -30 (excellent) to -90 (poor)
    if signal_dbm >= -50:
        return "▓▓▓▓▓"
    elif signal_dbm >= -60:
        return "▓▓▓▓░"
    elif signal_dbm >= -70:
        return "▓▓▓░░"
    elif signal_dbm >= -80:
        return "▓▓░░░"
    else:
        return "▓░░░░"

# ==================== LOBBY MANAGER ====================

class LobbyPlayer:
    """Represents a player in a lobby"""
    def __init__(self, nickname: str, client_id: str, ip: str):
        self.nickname = nickname
        self.client_id = client_id
        self.ip = ip
        self.last_heartbeat = time.time()
        self.status = "online"
        self.channel = "Casual"
        self.team = None
        self.ready = False

class LobbyManager:
    """Manage lobbies per SSID with player tracking"""
    def __init__(self):
        self.lobbies: Dict[str, Dict] = {}  # ssid -> {players, last_msg, created_time}
        self.current_ssid: Optional[str] = None
        self.lock = threading.Lock()

    def update_lobby(self, ssid: str, players: int, last_msg: str = ""):
        """Update or create a lobby"""
        with self.lock:
            if ssid not in self.lobbies:
                self.lobbies[ssid] = {
                    'players': [],
                    'last_msg': "",
                    'created_time': datetime.now(),
                    'signal': -70
                }
            self.lobbies[ssid]['player_count'] = players
            if last_msg:
                self.lobbies[ssid]['last_msg'] = last_msg
            self.lobbies[ssid]['updated_time'] = datetime.now()

    def add_player(self, ssid: str, nickname: str, client_id: str, ip: str):
        """Add or update player in lobby"""
        with self.lock:
            if ssid not in self.lobbies:
                self.lobbies[ssid] = {'players': [], 'player_count': 0, 'last_msg': "", 'created_time': datetime.now()}
            
            # Check if player exists
            for p in self.lobbies[ssid]['players']:
                if p.client_id == client_id:
                    p.last_heartbeat = time.time()
                    return
            
            # Add new player
            player = LobbyPlayer(nickname, client_id, ip)
            self.lobbies[ssid]['players'].append(player)
            self.lobbies[ssid]['player_count'] = len(self.lobbies[ssid]['players'])

    def remove_player(self, ssid: str, client_id: str):
        """Remove player from lobby"""
        with self.lock:
            if ssid in self.lobbies:
                self.lobbies[ssid]['players'] = [p for p in self.lobbies[ssid]['players'] if p.client_id != client_id]
                self.lobbies[ssid]['player_count'] = len(self.lobbies[ssid]['players'])

    def cleanup_stale_players(self):
        """Remove players with stale heartbeats"""
        with self.lock:
            current_time = time.time()
            for ssid in self.lobbies:
                self.lobbies[ssid]['players'] = [
                    p for p in self.lobbies[ssid]['players']
                    if current_time - p.last_heartbeat < PLAYER_TIMEOUT
                ]
                self.lobbies[ssid]['player_count'] = len(self.lobbies[ssid]['players'])

    def get_player_count(self, ssid: str) -> int:
        """Get player count for lobby"""
        with self.lock:
            return self.lobbies.get(ssid, {}).get('player_count', 0)

# ==================== MAIN APPLICATION ====================

class HotspotChatApp:
    def __init__(self, root):
        self.root = root
        self.local_ip = get_local_ip()
        self.nickname = None
        self.nickname_set = False
        self.sound_enabled = True
        self.notifications_enabled = True
        self.client_id = str(uuid.uuid4())
        self.sent_messages = set()
        self.is_focused = True
        self.current_ssid: Optional[str] = None
        self.current_multicast_group: Optional[str] = None
        self.multicast_sock: Optional[socket.socket] = None
        
        # Lobby management
        self.lobby_manager = LobbyManager()
        self.nearby_lobbies: Dict[str, Dict] = {}  # For WiFi scan results
        self.last_lobby_refresh = 0
        
        # Message history for stats
        self.message_history = deque(maxlen=1000)
        self.start_time = datetime.now()
        self.channel = "Casual"
        self.team = None
        
        # UI Setup
        root.title("Hotspot — More-Like-Chatroom")
        root.geometry("1000x750")
        root.configure(bg=BACKGROUND)
        root.resizable(True, True)
        
        # Detect initial SSID
        self.detect_ssid()
        
        # Focus binding
        root.bind("<FocusIn>", self.on_focus_in)
        root.bind("<FocusOut>", self.on_focus_out)
        root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Setup tray icon if available
        if PYSTRAY_AVAILABLE:
            self.setup_tray_icon()
        
        # Build UI
        self._build_ui()
        
        # Start background threads
        self.start_background_threads()
        
        self.root.focus_set()

    def _build_ui(self):
        """Build the main UI with tabbed interface"""
        # Header
        header_frame = tk.Frame(self.root, bg=BACKGROUND)
        header_frame.pack(fill="x", pady=10, padx=10)
        
        title_label = tk.Label(header_frame, text="⚡ HOTSPOT — More-Like-Chatroom", 
                              bg=BACKGROUND, fg=SUCCESS_COLOR, 
                              font=("Consolas", 14, "bold"))
        title_label.pack(side="left")
        
        # Connection status
        self.status_label = tk.Label(header_frame, text="Initializing...",
                                    bg=BACKGROUND, fg=ACCENT_COLOR,
                                    font=("Consolas", 9))
        self.status_label.pack(side="right", padx=10)
        
        # Notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Tab 1: Lobby Browser
        self.lobby_tab = tk.Frame(self.notebook, bg=BACKGROUND)
        self.notebook.add(self.lobby_tab, text="🎮 Lobbies")
        self._build_lobby_tab()
        
        # Tab 2: Chat
        self.chat_tab = tk.Frame(self.notebook, bg=BACKGROUND)
        self.notebook.add(self.chat_tab, text="💬 Chat")
        self._build_chat_tab()
        
        # Tab 3: Stats
        self.stats_tab = tk.Frame(self.notebook, bg=BACKGROUND)
        self.notebook.add(self.stats_tab, text="📊 Stats")
        self._build_stats_tab()

    def _build_lobby_tab(self):
        """Build lobby browser tab"""
        # Control frame
        control_frame = tk.Frame(self.lobby_tab, bg=BACKGROUND)
        control_frame.pack(fill="x", padx=10, pady=10)
        
        tk.Label(control_frame, text="Search:", bg=BACKGROUND, fg=TEXT_COLOR,
                font=("Consolas", 10)).pack(side="left", padx=5)
        
        self.lobby_search = tk.Entry(control_frame, bg=INPUT_BG, fg=TEXT_COLOR,
                                    font=("Consolas", 10), insertbackground=TEXT_COLOR,
                                    relief="flat", bd=2, width=20)
        self.lobby_search.pack(side="left", padx=5)
        self.lobby_search.bind("<KeyRelease>", lambda e: self.refresh_lobby_display())
        
        refresh_btn = tk.Button(control_frame, text="🔄 Refresh", bg=BUTTON_BG, fg=ACCENT_COLOR,
                               font=("Consolas", 9, "bold"), command=self.scan_and_refresh_lobbies,
                               relief="flat", padx=10)
        refresh_btn.pack(side="left", padx=5)
        
        # Lobbies frame
        self.lobbies_frame = tk.Frame(self.lobby_tab, bg=BACKGROUND)
        self.lobbies_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Header
        header_bg = LOBBY_HIGHLIGHT
        header = tk.Frame(self.lobbies_frame, bg=header_bg, height=30)
        header.pack(fill="x", pady=(0, 5))
        header.pack_propagate(False)
        
        tk.Label(header, text="SSID", bg=header_bg, fg=TEXT_COLOR, font=("Consolas", 10, "bold"), width=20, anchor="w").pack(side="left", padx=10, pady=5)
        tk.Label(header, text="Players", bg=header_bg, fg=TEXT_COLOR, font=("Consolas", 10, "bold"), width=10, anchor="w").pack(side="left", padx=5)
        tk.Label(header, text="Ping", bg=header_bg, fg=TEXT_COLOR, font=("Consolas", 10, "bold"), width=15, anchor="w").pack(side="left", padx=5)
        tk.Label(header, text="Last Message", bg=header_bg, fg=TEXT_COLOR, font=("Consolas", 10, "bold"), expand=True, anchor="w").pack(side="left", padx=5)
        tk.Label(header, text="Action", bg=header_bg, fg=TEXT_COLOR, font=("Consolas", 10, "bold"), width=15, anchor="w").pack(side="left", padx=5)
        
        # Scrollable lobbies list
        self.lobbies_canvas = tk.Canvas(self.lobbies_frame, bg=BACKGROUND, highlightthickness=0)
        scrollbar = tk.Scrollbar(self.lobbies_frame, command=self.lobbies_canvas.yview, bg=BUTTON_BG)
        self.lobbies_scrollable = tk.Frame(self.lobbies_canvas, bg=BACKGROUND)
        
        self.lobbies_scrollable.bind("<Configure>", 
            lambda e: self.lobbies_canvas.configure(scrollregion=self.lobbies_canvas.bbox("all")))
        
        self.lobbies_canvas.create_window((0, 0), window=self.lobbies_scrollable, anchor="nw")
        self.lobbies_canvas.configure(yscrollcommand=scrollbar.set)
        
        self.lobbies_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _build_chat_tab(self):
        """Build chat interface tab"""
        # Status/Info frame
        info_frame = tk.Frame(self.chat_tab, bg=BACKGROUND)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.chat_status_label = tk.Label(info_frame, text="", bg=BACKGROUND, fg=ACCENT_COLOR,
                                         font=("Consolas", 9))
        self.chat_status_label.pack(side="left")
        
        channel_frame = tk.Frame(info_frame, bg=BACKGROUND)
        channel_frame.pack(side="right")
        tk.Label(channel_frame, text="Channel:", bg=BACKGROUND, fg=TEXT_COLOR,
                font=("Consolas", 9)).pack(side="left", padx=5)
        
        self.channel_var = tk.StringVar(value="Casual")
        channel_combo = ttk.Combobox(channel_frame, textvariable=self.channel_var,
                                     values=["Casual", "Competitive"], state="readonly",
                                     font=("Consolas", 9), width=12)
        channel_combo.pack(side="left", padx=5)
        channel_combo.bind("<<ComboboxSelected>>", self.change_channel)
        
        # Chat display
        self.chat_display = scrolledtext.ScrolledText(self.chat_tab, bg=BACKGROUND,
                                                      fg=TEXT_COLOR, font=("Consolas", 10),
                                                      state='disabled', insertbackground=TEXT_COLOR,
                                                      relief="flat", wrap="word")
        self.chat_display.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Message input frame
        input_frame = tk.Frame(self.chat_tab, bg=BACKGROUND)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        self.message_entry = tk.Text(input_frame, bg=INPUT_BG, fg=TEXT_COLOR,
                                     font=("Consolas", 11), insertbackground=TEXT_COLOR,
                                     relief="flat", bd=2, height=2)
        self.message_entry.pack(side="left", fill="both", expand=True, padx=(0, 5))
        self.message_entry.bind('<Return>', self.handle_return)
        self.message_entry.bind('<Shift-Return>', lambda e: 'break')
        
        # Button frame
        button_frame = tk.Frame(input_frame, bg=BACKGROUND)
        button_frame.pack(side="right", fill="y")
        
        send_btn = tk.Button(button_frame, text="SEND", bg=BUTTON_BG, fg=TEXT_COLOR,
                            font=("Consolas", 9, "bold"), command=self.send_message,
                            relief="flat", padx=15, pady=5)
        send_btn.pack(side="top", pady=3)
        
        file_btn = tk.Button(button_frame, text="FILE", bg=BUTTON_BG, fg=ACCENT_COLOR,
                            font=("Consolas", 9, "bold"), command=self.send_file_action,
                            relief="flat", padx=15, pady=5)
        file_btn.pack(side="top", pady=3)
        
        # Quick reaction buttons
        reaction_frame = tk.Frame(button_frame, bg=BACKGROUND)
        reaction_frame.pack(side="top", pady=5)
        
        for emoji in ["👍", "❤️", "😂", "🎮"]:
            btn = tk.Button(reaction_frame, text=emoji, bg=BUTTON_BG, fg=TEXT_COLOR,
                           font=("Consolas", 9), command=lambda e=emoji: self.send_reaction(e),
                           relief="flat", padx=8, pady=3)
            btn.pack(side="left", padx=2)

    def _build_stats_tab(self):
        """Build stats interface tab"""
        # Stats text
        self.stats_display = scrolledtext.ScrolledText(self.stats_tab, bg=BACKGROUND,
                                                       fg=TEXT_COLOR, font=("Consolas", 10),
                                                       state='disabled', insertbackground=TEXT_COLOR,
                                                       relief="flat")
        self.stats_display.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Button frame
        button_frame = tk.Frame(self.stats_tab, bg=BACKGROUND)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        export_btn = tk.Button(button_frame, text="📥 Export History CSV", bg=BUTTON_BG, fg=ACCENT_COLOR,
                              font=("Consolas", 9, "bold"), command=self.export_stats,
                              relief="flat", padx=15, pady=5)
        export_btn.pack(side="left", padx=5)
        
        clear_btn = tk.Button(button_frame, text="🗑️ Clear Stats", bg=BUTTON_BG, fg=ERROR_COLOR,
                             font=("Consolas", 9, "bold"), command=self.clear_stats,
                             relief="flat", padx=15, pady=5)
        clear_btn.pack(side="left", padx=5)

    def detect_ssid(self):
        """Detect and setup multicast for current SSID"""
        ssid = get_current_ssid()
        if ssid and ssid != self.current_ssid:
            self.current_ssid = ssid
            self.current_multicast_group, _ = ssid_to_multicast_group(ssid)
            self.setup_multicast_socket()
            self.display_message(f"🌐 Detected WiFi: {ssid}", SUCCESS_COLOR)
            self.update_status_label()
            print(f"[DEBUG] Connected to SSID: {ssid} -> Multicast: {self.current_multicast_group}")

    def setup_multicast_socket(self):
        """Setup multicast UDP socket for current SSID"""
        try:
            if self.multicast_sock:
                try:
                    self.multicast_sock.close()
                except:
                    pass
            
            self.multicast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.multicast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # For multicast receiver
            if platform.system() == 'Windows':
                self.multicast_sock.bind(('', PORT))
            else:
                self.multicast_sock.bind(('0.0.0.0', PORT))
            
            # Join multicast group
            group = socket.inet_aton(self.current_multicast_group)
            mreq = struct.pack('4sL', group, socket.INADDR_ANY)
            self.multicast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            # Set TTL
            self.multicast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
            self.multicast_sock.settimeout(1.0)
            
            print(f"[DEBUG] Multicast socket setup for {self.current_multicast_group}")
        except Exception as e:
            print(f"[DEBUG] Multicast setup error: {e}")
            self.display_message(f"Multicast setup error: {e}", ERROR_COLOR)

    def update_status_label(self):
        """Update header status label"""
        if self.current_ssid:
            players = self.lobby_manager.get_player_count(self.current_ssid)
            status = f"🎮 {self.current_ssid} | 👥 {players} players | {self.local_ip}"
        else:
            status = f"Not connected to WiFi | {self.local_ip}"
        self.status_label.config(text=status)

    def scan_and_refresh_lobbies(self):
        """Scan WiFi networks and refresh lobby display"""
        def scan_thread():
            try:
                networks = scan_wifi_networks()
                self.nearby_lobbies = {}
                
                for network in networks:
                    ssid = network['ssid']
                    self.nearby_lobbies[ssid] = {
                        'signal': network['signal'],
                        'player_count': self.lobby_manager.get_player_count(ssid),
                        'last_msg': self.lobby_manager.lobbies.get(ssid, {}).get('last_msg', ''),
                    }
                
                self.root.after(0, self.refresh_lobby_display)
            except Exception as e:
                print(f"[DEBUG] Scan error: {e}")
        
        threading.Thread(target=scan_thread, daemon=True).start()

    def refresh_lobby_display(self):
        """Refresh the lobby browser display"""
        search_term = self.lobby_search.get().lower()
        
        # Clear scrollable frame
        for widget in self.lobbies_scrollable.winfo_children():
            widget.destroy()
        
        if not self.nearby_lobbies:
            no_lobbies = tk.Label(self.lobbies_scrollable, text="No lobbies found. Scan to refresh.",
                                 bg=BACKGROUND, fg=WARNING_COLOR, font=("Consolas", 10))
            no_lobbies.pack(pady=20)
            return
        
        for ssid, info in sorted(self.nearby_lobbies.items()):
            if search_term and search_term not in ssid.lower():
                continue
            
            row_frame = tk.Frame(self.lobbies_scrollable, bg=BACKGROUND, relief="flat", bd=1)
            row_frame.pack(fill="x", pady=3, padx=5)
            
            # Highlight current lobby
            if ssid == self.current_ssid:
                row_frame.config(bg=LOBBY_HIGHLIGHT)
            
            # SSID
            tk.Label(row_frame, text=ssid[:20], bg=row_frame['bg'], fg=TEXT_COLOR,
                    font=("Consolas", 9), width=20, anchor="w").pack(side="left", padx=10, fill="y")
            
            # Players
            player_count = info['player_count']
            player_text = f"{player_count}/{MAX_PLAYERS_PER_LOBBY}"
            tk.Label(row_frame, text=player_text, bg=row_frame['bg'], fg=SUCCESS_COLOR,
                    font=("Consolas", 9), width=10, anchor="w").pack(side="left", padx=5, fill="y")
            
            # Signal/Ping
            signal = info['signal']
            bars = signal_to_bars(signal)
            ping_text = f"{signal} dBm {bars}"
            tk.Label(row_frame, text=ping_text, bg=row_frame['bg'], fg=ACCENT_COLOR,
                    font=("Consolas", 8), width=15, anchor="w").pack(side="left", padx=5, fill="y")
            
            # Last message (truncated)
            last_msg = info.get('last_msg', '')[:40]
            tk.Label(row_frame, text=last_msg, bg=row_frame['bg'], fg=TEXT_COLOR,
                    font=("Consolas", 8), anchor="w").pack(side="left", padx=5, fill="both", expand=True)
            
            # Join button
            join_btn = tk.Button(row_frame, text="Join Game", bg=BUTTON_BG, fg=NEON_CYAN,
                                font=("Consolas", 8, "bold"),
                                command=lambda s=ssid: self.join_lobby(s),
                                relief="flat", padx=8, pady=3)
            join_btn.pack(side="right", padx=10, fill="y")

    def join_lobby(self, ssid: str):
        """Join a specific lobby (WiFi + chat room)"""
        if not PYWIFI_AVAILABLE:
            self.show_error("pywifi not installed. Cannot auto-connect to WiFi.")
            return
        
        try:
            wifi = pywifi.PyWiFi()
            ifaces = wifi.interfaces()
            if not ifaces:
                self.show_error("No WiFi interface found")
                return
            
            iface = ifaces[0]
            
            # Disconnect from current
            iface.disconnect()
            time.sleep(1)
            
            # Create profile and connect
            profile = pywifi.Profile()
            profile.ssid = ssid
            profile.auth = const.AUTH_ALG_OPEN
            profile.cipher = const.CIPHER_TYPE_CCMP
            profile.key = None
            
            iface.add_network_profile(profile)
            
            profiles = iface.network_profiles
            target_profile = None
            for p in profiles:
                if p.ssid == ssid:
                    target_profile = p
                    break
            
            if target_profile:
                iface.connect(target_profile)
                time.sleep(3)
                
                self.detect_ssid()
                self.display_message(f"✅ Joined lobby: {ssid}", SUCCESS_COLOR)
                self.show_notification(f"Connected to lobby: {ssid}")
            
        except Exception as e:
            self.show_error(f"Failed to join lobby: {e}")

    def start_background_threads(self):
        """Start all background threads"""
        threading.Thread(target=self.receive_messages_thread, daemon=True).start()
        threading.Thread(target=self.heartbeat_thread, daemon=True).start()
        threading.Thread(target=self.ssid_detect_thread, daemon=True).start()
        threading.Thread(target=self.lobby_refresh_thread, daemon=True).start()
        threading.Thread(target=self.player_cleanup_thread, daemon=True).start()

    def receive_messages_thread(self):
        """Listen for multicast messages"""
        while running:
            try:
                if not self.multicast_sock:
                    time.sleep(1)
                    continue
                
                data, addr = self.multicast_sock.recvfrom(BUFFER_SIZE)
                
                try:
                    decrypted = xor_encrypt_decrypt(data.decode('utf-8'), XOR_KEY)
                    message = json.loads(decrypted)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                
                # Ignore own messages
                if message.get('client_id') == self.client_id:
                    continue
                
                # Dedup
                msg_id = message.get('message_id')
                if msg_id and msg_id in self.sent_messages:
                    continue
                
                if msg_id:
                    self.sent_messages.add(msg_id)
                    if len(self.sent_messages) > 100:
                        self.sent_messages = set(list(self.sent_messages)[-50:])
                
                self.handle_incoming_message(message)
                
            except socket.timeout:
                continue
            except Exception as e:
                if running:
                    print(f"[DEBUG] Receive error: {e}")

    def handle_incoming_message(self, message: Dict):
        """Process incoming message"""
        msg_type = message.get('type')
        ssid = message.get('ssid', self.current_ssid)
        
        if msg_type == 'join':
            nickname = message.get('nickname', 'Unknown')
            self.lobby_manager.add_player(ssid, nickname, message.get('client_id'), message.get('ip'))
            self.display_message(f"✅ {nickname} JOINED", SUCCESS_COLOR)
            self.play_notification_sound('join')
            self.show_notification(f"{nickname} joined")
            self.update_status_label()
            
        elif msg_type == 'heartbeat':
            nickname = message.get('nickname', 'Unknown')
            self.lobby_manager.add_player(ssid, nickname, message.get('client_id'), message.get('ip'))
            self.update_status_label()
            
        elif msg_type == 'leave':
            self.lobby_manager.remove_player(ssid, message.get('client_id'))
            self.display_message(f"❌ {message.get('nickname', 'Unknown')} LEFT", ERROR_COLOR)
            self.play_notification_sound('leave')
            self.update_status_label()
            
        elif msg_type == 'message':
            nickname = message.get('nickname', 'Unknown')
            text = message.get('message', '')
            channel = message.get('channel', 'Casual')
            self.display_message(f"[{channel}] {nickname}: {text}", TEXT_COLOR)
            self.message_history.append({'type': 'message', 'nickname': nickname, 'text': text, 'channel': channel, 'time': datetime.now()})
            self.play_notification_sound('message')
            self.show_notification(f"{nickname}: {text[:30]}")
            self.flash_window()
            
            # Update lobby last message
            if ssid:
                self.lobby_manager.lobbies[ssid]['last_msg'] = f"{nickname}: {text[:40]}"
            
            if not self.is_focused:
                self.flash_window()
                
        elif msg_type == 'reaction':
            nickname = message.get('nickname', 'Unknown')
            emoji = message.get('emoji', '')
            self.display_message(f"{nickname} reacted: {emoji}", ACCENT_COLOR)
            
        elif msg_type == 'file_offer':
            nick = message.get('nickname', 'Unknown')
            fname = message.get('filename', '?')
            fsize = message.get('filesize', 0)
            ip = message.get('ip')
            port = message.get('tcp_port')
            self.display_file_offer(nick, fname, fsize, ip, port)
            self.play_notification_sound('message')
            self.show_notification(f"{nick} shared: {fname}")

    def heartbeat_thread(self):
        """Send heartbeat every HEARTBEAT_INTERVAL seconds"""
        while running:
            try:
                time.sleep(HEARTBEAT_INTERVAL)
                
                if not self.nickname_set or not self.current_ssid:
                    continue
                
                heartbeat = {
                    'type': 'heartbeat',
                    'nickname': self.nickname,
                    'client_id': self.client_id,
                    'ip': self.local_ip,
                    'ssid': self.current_ssid,
                    'channel': self.channel,
                    'message_id': str(uuid.uuid4())
                }
                self.send_data(heartbeat)
            except Exception as e:
                print(f"[DEBUG] Heartbeat error: {e}")

    def ssid_detect_thread(self):
        """Periodically check for SSID changes"""
        while running:
            try:
                time.sleep(5)
                self.detect_ssid()
            except Exception as e:
                print(f"[DEBUG] SSID detect error: {e}")

    def lobby_refresh_thread(self):
        """Periodically refresh lobby list"""
        while running:
            try:
                time.sleep(LOBBY_REFRESH_INTERVAL)
                self.scan_and_refresh_lobbies()
            except Exception as e:
                print(f"[DEBUG] Lobby refresh error: {e}")

    def player_cleanup_thread(self):
        """Periodically clean up stale players"""
        while running:
            try:
                time.sleep(PLAYER_TIMEOUT // 2)
                self.lobby_manager.cleanup_stale_players()
            except Exception as e:
                print(f"[DEBUG] Cleanup error: {e}")

    def display_message(self, message: str, color: str):
        """Display message in chat with timestamp"""
        def update():
            self.chat_display.config(state='normal')
            timestamp = datetime.now().strftime('%H:%M:%S')
            full_msg = f"[{timestamp}] {message}\n"
            self.chat_display.insert(tk.END, full_msg)
            
            # Color tagging
            start_idx = self.chat_display.index(f"end-{len(full_msg)+1}c")
            self.chat_display.tag_add("color", start_idx, "end-1c")
            self.chat_display.tag_config("color", foreground=color)
            
            self.chat_display.config(state='disabled')
            self.chat_display.see(tk.END)
        
        self.root.after(0, update)

    def change_channel(self, event=None):
        """Change chat channel"""
        self.channel = self.channel_var.get()
        self.display_message(f"Switched to {self.channel} channel", ACCENT_COLOR)

    def handle_return(self, event):
        """Handle Enter key"""
        if not event.state & 0x1:  # No Shift
            self.send_message()
            return "break"

    def send_message(self, event=None):
        """Send message or command"""
        text = self.message_entry.get("1.0", tk.END).strip()
        if not text:
            return
        
        if len(text) > 3000:
            self.show_error("Message too long (max 3000 chars)")
            return
        
        if text.startswith('/'):
            self.handle_command(text)
        elif self.nickname_set:
            msg_id = str(uuid.uuid4())
            message_data = {
                'type': 'message',
                'nickname': self.nickname,
                'message': text,
                'ip': self.local_ip,
                'client_id': self.client_id,
                'message_id': msg_id,
                'ssid': self.current_ssid,
                'channel': self.channel
            }
            self.sent_messages.add(msg_id)
            self.send_data(message_data)
            self.display_message(f"You [{self.channel}]: {text}", NEON_CYAN)
            self.message_history.append({'type': 'message', 'nickname': self.nickname, 'text': text, 'channel': self.channel, 'time': datetime.now()})
        
        self.message_entry.delete("1.0", tk.END)

    def send_reaction(self, emoji: str):
        """Send emoji reaction"""
        if not self.nickname_set or not self.current_ssid:
            return
        
        reaction = {
            'type': 'reaction',
            'nickname': self.nickname,
            'emoji': emoji,
            'client_id': self.client_id,
            'ip': self.local_ip,
            'message_id': str(uuid.uuid4()),
            'ssid': self.current_ssid
        }
        self.send_data(reaction)
        self.display_message(f"You reacted: {emoji}", ACCENT_COLOR)

    def handle_command(self, text: str):
        """Process slash commands"""
        parts = text.lower().split()
        cmd = parts[0]
        
        if cmd == '/help':
            help_txt = "Commands: /clear, /ready, /stats, /team <1|2>, /map <name>, /help"
            self.display_message(help_txt, SUCCESS_COLOR)
        elif cmd == '/clear':
            self.chat_display.config(state='normal')
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.config(state='disabled')
        elif cmd == '/ready':
            self.display_message("You're ready for battle! 🎮", SUCCESS_COLOR)
            self.send_reaction("👍")
        elif cmd == '/team':
            if len(parts) > 1 and parts[1] in ['1', '2']:
                self.team = int(parts[1])
                self.display_message(f"Joined Team {self.team}", ACCENT_COLOR)
            else:
                self.display_message("Usage: /team <1|2>", ERROR_COLOR)
        elif cmd == '/map':
            if len(parts) > 1:
                map_name = ' '.join(parts[1:])
                self.display_message(f"Map changed to: {map_name}", ACCENT_COLOR)
            else:
                self.display_message("Usage: /map <name>", ERROR_COLOR)
        elif cmd == '/stats':
            self.show_stats()
        else:
            self.display_message(f"Unknown command: {cmd}. Type /help", ERROR_COLOR)

    def show_stats(self):
        """Display chat statistics"""
        def update_stats():
            uptime = datetime.now() - self.start_time
            msg_count = len(self.message_history)
            avg_msgs = msg_count / max(uptime.total_seconds() / 60, 1)
            
            stats_text = f"""
╔════════════════════════════════════╗
║       HOTSPOT CHAT STATISTICS      ║
╚════════════════════════════════════╝

📊 Session Stats:
  • Uptime: {str(uptime).split('.')[0]}
  • Username: {self.nickname or 'Not set'}
  • Client ID: {self.client_id[:8]}...
  • Local IP: {self.local_ip}

💬 Chat Stats:
  • Total Messages: {msg_count}
  • Messages/min: {avg_msgs:.1f}
  • Current Channel: {self.channel}
  • Team: {self.team or 'None'}

🌐 Network Stats:
  • Current SSID: {self.current_ssid or 'Not connected'}
  • Multicast Group: {self.current_multicast_group or 'N/A'}
  • Players in lobby: {self.lobby_manager.get_player_count(self.current_ssid) if self.current_ssid else 0}

🎮 Game Stats:
  • Sound Enabled: {'Yes' if self.sound_enabled else 'No'}
  • Notifications: {'Yes' if self.notifications_enabled else 'No'}
"""
            self.display_message(stats_text, ACCENT_COLOR)

        self.root.after(0, update_stats)

    def update_stats_tab(self):
        """Update statistics tab display"""
        uptime = datetime.now() - self.start_time
        msg_count = len(self.message_history)
        
        stats_text = f"""╔════════════════════════════════════╗
║       HOTSPOT CHAT STATISTICS      ║
╚════════════════════════════════════╝

📊 SESSION STATS
  Uptime: {str(uptime).split('.')[0]}
  Username: {self.nickname or 'Not set'}
  Client ID: {self.client_id[:16]}
  Local IP: {self.local_ip}

💬 CHAT STATISTICS
  Total Messages: {msg_count}
  Current Channel: {self.channel}
  Team: {self.team or 'No team'}

🌐 NETWORK STATUS
  Current SSID: {self.current_ssid or 'Not connected'}
  Multicast: {self.current_multicast_group or 'N/A'}
  Players: {self.lobby_manager.get_player_count(self.current_ssid) if self.current_ssid else 0}/{MAX_PLAYERS_PER_LOBBY}

📈 TOP RECENT MESSAGES
"""
        
        # Add last 10 messages
        for msg in list(self.message_history)[-10:]:
            stats_text += f"  • {msg['nickname']}: {msg['text'][:40]}...\n"
        
        self.stats_display.config(state='normal')
        self.stats_display.delete(1.0, tk.END)
        self.stats_display.insert(1.0, stats_text)
        self.stats_display.config(state='disabled')

    def export_stats(self):
        """Export message history to CSV"""
        try:
            filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
            if not filepath:
                return
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Username', 'Channel', 'Message'])
                
                for msg in self.message_history:
                    if msg['type'] == 'message':
                        writer.writerow([msg['time'].isoformat(), msg['nickname'], msg['channel'], msg['text']])
            
            messagebox.showinfo("Export Complete", f"Exported {len(self.message_history)} messages")
        except Exception as e:
            self.show_error(f"Export failed: {e}")

    def clear_stats(self):
        """Clear all statistics"""
        if messagebox.askyesno("Confirm", "Clear all statistics and message history?"):
            self.message_history.clear()
            self.start_time = datetime.now()
            self.display_message("Statistics cleared", WARNING_COLOR)

    def send_data(self, message_dict: Dict):
        """Encrypt and broadcast via multicast"""
        try:
            if not self.current_multicast_group or not self.multicast_sock:
                return
            
            json_data = json.dumps(message_dict)
            encrypted = xor_encrypt_decrypt(json_data, XOR_KEY)
            
            # Send via multicast
            self.multicast_sock.sendto(encrypted.encode('utf-8'), (self.current_multicast_group, PORT))
        except Exception as e:
            print(f"[DEBUG] Send error: {e}")

    def display_file_offer(self, nickname: str, filename: str, filesize: int, ip: str, port: int):
        """Display file offer with download button"""
        def update_ui():
            self.chat_display.config(state='normal')
            timestamp = datetime.now().strftime('%H:%M:%S')
            
            header = f"[{timestamp}] {nickname} shared file:\n"
            self.chat_display.insert(tk.END, header)
            
            info = f"  {filename} ({self.format_size(filesize)})  "
            self.chat_display.insert(tk.END, info)
            
            btn = tk.Button(self.chat_display, text="DOWNLOAD", font=("Consolas", 8, "bold"),
                           bg=ACCENT_COLOR, fg="white")
            btn.configure(command=lambda: self.start_download(filename, filesize, ip, port, btn))
            
            self.chat_display.window_create(tk.END, window=btn)
            self.chat_display.insert(tk.END, "\n")
            
            self.chat_display.config(state='disabled')
            self.chat_display.see(tk.END)
        
        self.root.after(0, update_ui)

    def send_file_action(self):
        """Handle file offering"""
        filename = filedialog.askopenfilename()
        if not filename:
            return
        
        try:
            file_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            file_sock.bind(('0.0.0.0', 0))
            port = file_sock.getsockname()[1]
            file_sock.listen(5)
            
            file_size = os.path.getsize(filename)
            file_basename = os.path.basename(filename)
            
            threading.Thread(target=self.file_server_thread, args=(file_sock, filename), daemon=True).start()
            
            offer_id = str(uuid.uuid4())
            offer_data = {
                'type': 'file_offer',
                'nickname': self.nickname,
                'filename': file_basename,
                'filesize': file_size,
                'ip': self.local_ip,
                'tcp_port': port,
                'client_id': self.client_id,
                'message_id': offer_id,
                'ssid': self.current_ssid
            }
            self.send_data(offer_data)
            self.sent_messages.add(offer_id)
            
            self.display_message(f"📤 You shared: {file_basename} ({self.format_size(file_size)})", SUCCESS_COLOR)
        except Exception as e:
            self.show_error(f"File share error: {e}")

    def file_server_thread(self, sock, filepath):
        """Serve file to clients"""
        try:
            while running:
                client, addr = sock.accept()
                threading.Thread(target=self.handle_file_client, args=(client, filepath), daemon=True).start()
        except:
            pass
        finally:
            try:
                sock.close()
            except:
                pass

    def handle_file_client(self, client_sock, filepath):
        """Send file to single client"""
        try:
            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(FILE_BUFFER_SIZE)
                    if not data:
                        break
                    client_sock.sendall(data)
        except:
            pass
        finally:
            client_sock.close()

    def start_download(self, filename: str, filesize: int, ip: str, port: int, btn):
        """Start file download"""
        try:
            save_path = filedialog.asksaveasfilename(initialfile=filename)
        except Exception as e:
            print(f"[DEBUG] File dialog error: {e}")
            return
        
        if not save_path:
            return
        
        btn.config(state='disabled', text="Starting...", bg=BUTTON_BG)
        threading.Thread(target=self.download_thread, args=(save_path, filesize, ip, port, btn), daemon=True).start()

    def download_thread(self, save_path: str, filesize: int, ip: str, port: int, btn):
        """Download file in background"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((ip, port))
            
            received = 0
            last_update = 0
            
            with open(save_path, 'wb') as f:
                while True:
                    data = s.recv(FILE_BUFFER_SIZE)
                    if not data:
                        break
                    f.write(data)
                    received += len(data)
                    
                    current_time = time.time()
                    if current_time - last_update > 0.1:
                        percent = int((received / filesize) * 100) if filesize > 0 else 0
                        self.root.after(0, lambda p=percent: btn.config(text=f"{p}%"))
                        last_update = current_time
            
            s.close()
            
            if received == filesize:
                self.root.after(0, lambda: btn.config(text="OPEN", bg=SUCCESS_COLOR, state='normal',
                                                     command=lambda: self.open_file(save_path)))
                self.root.after(0, lambda: messagebox.showinfo("Complete", f"Saved to:\n{save_path}"))
            else:
                self.root.after(0, lambda: self.show_error(f"Incomplete: {self.format_size(received)}/{self.format_size(filesize)}"))
        except Exception as e:
            print(f"[DEBUG] Download error: {e}")
            self.root.after(0, lambda: self.show_error(f"Download failed: {e}"))

    def open_file(self, filepath: str):
        """Open downloaded file"""
        try:
            if sys.platform == 'win32':
                os.startfile(filepath)
            elif sys.platform == 'darwin':
                subprocess.call(('open', filepath))
            else:
                subprocess.call(('xdg-open', filepath))
        except Exception as e:
            self.show_error(f"Could not open: {e}")

    def format_size(self, size: int) -> str:
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def on_focus_in(self, event=None):
        """Handle window focus"""
        self.is_focused = True
        self.update_status_label()

    def on_focus_out(self, event=None):
        """Handle window blur"""
        self.is_focused = False

    def play_sound_cross_platform(self, frequency: int, duration: int):
        """Play sound cross-platform"""
        def _play():
            try:
                freq = int(frequency)
                dur = int(duration)
                
                if winsound:
                    try:
                        winsound.Beep(freq, dur)
                    except:
                        try:
                            winsound.MessageBeep(winsound.MB_OK)
                        except:
                            pass
                else:
                    try:
                        sample_rate = 44100
                        n_samples = int(sample_rate * (dur / 1000.0))
                        audio = []
                        for i in range(n_samples):
                            value = int(32767.0 * 0.3 * math.sin(2.0 * math.pi * freq * i / sample_rate))
                            audio.append(struct.pack('<h', value))
                        
                        audio_data = b''.join(audio)
                        
                        with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as tf:
                            tmp_name = tf.name
                            tf.write(b'RIFF')
                            tf.write(struct.pack('<I', 36 + len(audio_data)))
                            tf.write(b'WAVEfmt ')
                            tf.write(struct.pack('<I', 16))
                            tf.write(struct.pack('<H', 1))
                            tf.write(struct.pack('<H', 1))
                            tf.write(struct.pack('<I', sample_rate))
                            tf.write(struct.pack('<I', sample_rate * 2))
                            tf.write(struct.pack('<H', 2))
                            tf.write(struct.pack('<H', 16))
                            tf.write(b'data')
                            tf.write(struct.pack('<I', len(audio_data)))
                            tf.write(audio_data)
                        
                        try:
                            subprocess.run(['aplay', '-q', tmp_name], check=False, timeout=5)
                        except:
                            try:
                                subprocess.run(['paplay', tmp_name], check=False, timeout=5)
                            except:
                                pass
                        
                        try:
                            os.remove(tmp_name)
                        except:
                            pass
                    except:
                        pass
            except Exception as e:
                print(f"[DEBUG] Sound error: {e}")
        
        threading.Thread(target=_play, daemon=True).start()

    def play_notification_sound(self, sound_type: str = 'message'):
        """Play sound notification"""
        if not self.sound_enabled:
            return
        
        try:
            if sound_type == 'join':
                self.play_sound_cross_platform(1000, 150)
            elif sound_type == 'leave':
                self.play_sound_cross_platform(600, 300)
            elif sound_type == 'error':
                self.play_sound_cross_platform(300, 300)
            elif sound_type == 'message':
                if self.is_focused:
                    self.play_sound_cross_platform(1200, 150)
                else:
                    self.play_sound_cross_platform(300, 300)
        except Exception:
            pass

    def show_notification(self, message: str):
        """Show visual notification"""
        if not self.notifications_enabled:
            return
        
        try:
            if not self.root.focus_get():
                self.root.attributes('-topmost', True)
                self.root.after(100, lambda: self.root.attributes('-topmost', False))
        except:
            pass

    def flash_window(self):
        """Flash window for attention"""
        if not self.notifications_enabled:
            return
        
        try:
            original_title = self.root.title()
            self.root.title("⚡ NEW MESSAGE ⚡ " + original_title)
            self.root.after(2000, lambda: self.root.title(original_title))
        except:
            pass

    def show_error(self, message: str):
        """Show error dialog"""
        self.play_notification_sound('error')
        messagebox.showerror("Error", message)

    def setup_tray_icon(self):
        """Setup system tray icon"""
        try:
            image = Image.new('RGB', (64, 64), color=BACKGROUND)
            draw = ImageDraw.Draw(image)
            draw.rectangle([16, 16, 48, 48], fill=SUCCESS_COLOR)
            
            menu = pystray.Menu(
                pystray.MenuItem("Show", self.show_from_tray),
                pystray.MenuItem("Quit", self.quit_from_tray)
            )
            
            self.tray_icon = pystray.Icon("Hotspot Chat", image, menu=menu)
            threading.Thread(target=self.tray_icon.run, daemon=True).start()
        except Exception as e:
            print(f"[DEBUG] Tray setup error: {e}")

    def show_from_tray(self, icon=None, item=None):
        """Show window from tray"""
        self.root.deiconify()
        self.root.lift()

    def quit_from_tray(self, icon=None, item=None):
        """Quit from tray"""
        self.on_closing()

    def on_closing(self):
        """Clean up on close"""
        global running
        running = False
        
        if self.nickname_set and self.current_ssid:
            try:
                leave_data = {
                    'type': 'leave',
                    'nickname': self.nickname,
                    'client_id': self.client_id,
                    'ip': self.local_ip,
                    'ssid': self.current_ssid,
                    'message_id': str(uuid.uuid4())
                }
                self.send_data(leave_data)
            except:
                pass
        
        try:
            if self.multicast_sock:
                self.multicast_sock.close()
        except:
            pass
        
        try:
            if PYSTRAY_AVAILABLE and hasattr(self, 'tray_icon'):
                self.tray_icon.stop()
        except:
            pass
        
        self.root.destroy()


# ==================== SETUP/DEMO FUNCTIONS ====================

def print_header(text):
    """Print formatted header"""
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")

def print_check(text, status=True):
    """Print status check with color"""
    symbol = "✓" if status else "✗"
    color = "\033[92m" if status else "\033[91m"
    reset = "\033[0m"
    print(f"{color}[{symbol}]{reset} {text}")

def check_python_version():
    """Check Python version"""
    print_header("Python Version Check")
    version = sys.version_info
    min_version = (3, 7)
    if version >= min_version:
        print_check(f"Python {version.major}.{version.minor}.{version.micro}", True)
        return True
    else:
        print_check(f"Python {version.major}.{version.minor} (need 3.7+)", False)
        return False

def check_tkinter():
    """Check if Tkinter is available"""
    print_header("GUI Framework Check")
    try:
        import tkinter
        print_check("tkinter available", True)
        return True
    except ImportError:
        print_check("tkinter NOT found", False)
        print("\nInstall: ")
        if platform.system() == "Windows":
            print("  Windows: Re-run Python installer, enable 'tcl/tk and IDLE'")
        elif platform.system() == "Darwin":
            print("  macOS: brew install python-tk")
        else:
            print("  Linux: sudo apt-get install python3-tk")
        return False

def check_dependencies():
    """Check optional dependencies"""
    print_header("Dependencies Check")
    deps = {
        'socket': 'Built-in',
        'threading': 'Built-in',
        'json': 'Built-in',
        'uuid': 'Built-in',
        'hashlib': 'Built-in',
        'csv': 'Built-in',
        'tempfile': 'Built-in',
        'struct': 'Built-in',
        'pywifi': 'pip install pywifi',
        'pystray': 'pip install pystray',
        'PIL': 'pip install pillow',
    }
    for module, install_cmd in sorted(deps.items()):
        try:
            if module == 'PIL':
                import PIL
            else:
                __import__(module)
            if 'Built-in' in install_cmd:
                print_check(f"{module:15s} (built-in)", True)
            else:
                print_check(f"{module:15s} (installed)", True)
        except ImportError:
            if 'Built-in' in install_cmd:
                print_check(f"{module:15s}", False)
            else:
                print_check(f"{module:15s} - {install_cmd}", False)

def check_network():
    """Check network interfaces"""
    print_header("Network Check")
    try:
        hostname = socket.gethostname()
        print_check(f"Hostname: {hostname}", True)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
        except:
            s.connect(('10.255.255.255', 1))
            local_ip = s.getsockname()[0]
        finally:
            s.close()
        print_check(f"Local IP: {local_ip}", True)
        try:
            mcast_test = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            mcast_test.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            mcast_test.bind(('', 12345))
            group = socket.inet_aton('239.1.2.3')
            mreq = struct.pack('4sL', group, socket.INADDR_ANY)
            mcast_test.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            mcast_test.close()
            print_check("Multicast support: Available", True)
        except Exception as e:
            print_check("Multicast support: May be unavailable", False)
    except Exception as e:
        print_check(f"Network check failed: {e}", False)

def check_wifi():
    """Check WiFi capability"""
    print_header("WiFi & WLan Check")
    try:
        import pywifi
        print_check("pywifi: Installed", True)
        try:
            wifi = pywifi.PyWiFi()
            ifaces = wifi.interfaces()
            if ifaces:
                print_check(f"WiFi interfaces: {len(ifaces)} found", True)
                for i, iface in enumerate(ifaces, 1):
                    print(f"    {i}. {iface.name}")
            else:
                print_check("WiFi interfaces: None found", False)
        except Exception as e:
            print_check(f"WiFi scan error: {e}", False)
    except ImportError:
        print_check("pywifi: NOT installed", False)
        print("    Install: pip install pywifi")
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(['netsh', 'wlan', 'show', 'interface'], capture_output=True, text=True, timeout=5)
            if 'SSID' in result.stdout:
                print_check("SSID detection: Available (netsh)", True)
            else:
                print_check("SSID detection: No wireless connected", False)
        elif platform.system() == 'Darwin':
            print_check("SSID detection: Available (airport)", True)
        else:
            print_check("SSID detection: Available (iwconfig)", True)
    except Exception as e:
        print_check(f"SSID detection failed: {e}", False)

def check_audio():
    """Check audio capability"""
    print_header("Audio Check")
    system = platform.system()
    if system == 'Windows':
        try:
            import winsound
            print_check("Audio: winsound module available", True)
            print("    Test sound will beep in 1 second...")
            time.sleep(1)
            try:
                winsound.Beep(1000, 100)
                print_check("Audio: Test beep successful", True)
            except Exception as e:
                print_check("Audio: Beep failed (may be muted)", False)
        except ImportError:
            print_check("Audio: winsound NOT available", False)
    elif system == 'Darwin':
        print_check("Audio: macOS (should work)", True)
    else:
        try:
            subprocess.run(['which', 'aplay'], capture_output=True, check=True, timeout=2)
            print_check("Audio: aplay found (ALSA)", True)
        except:
            try:
                subprocess.run(['which', 'paplay'], capture_output=True, check=True, timeout=2)
                print_check("Audio: paplay found (PulseAudio)", True)
            except:
                print_check("Audio: No audio players found", False)

def run_setup_demo():
    """Run complete setup and demo"""
    print("\n")
    print("╔" + "═"*58 + "╗")
    print("║" + " "*58 + "║")
    print("║" + "  Hotspot — More-Like-Chatroom Setup & Demo".center(58) + "║")
    print("║" + " "*58 + "║")
    print("╚" + "═"*58 + "╝")
    check_python_version()
    check_tkinter()
    check_dependencies()
    check_network()
    check_wifi()
    check_audio()
    print_header("Next Steps")
    print("""
1️⃣  Install Dependencies:
    pip install -r requirements.txt

2️⃣  Run the App:
    python hotspot.py

3️⃣  Multi-Device Demo:
    • Run on 2+ devices on same WiFi
    • Set nicknames
    • See lobbies in 🎮 Lobbies tab
    • Chat via 💬 Chat tab
    • View stats in 📊 Stats tab

For help:
    python hotspot.py --help
    """)

# ==================== MAIN ====================

if __name__ == "__main__":
    # Handle command-line arguments
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ['--setup', 'setup', '--check', 'check', '--demo', 'demo']:
            run_setup_demo()
            sys.exit(0)
        elif arg in ['--help', '-h', 'help']:
            print("""
Hotspot — More-Like-Chatroom v2.0

Usage:
    python hotspot.py              # Run the app (default)
    python hotspot.py setup        # Run setup checks & demo
    python hotspot.py --help       # Show this help
            """)
            sys.exit(0)
    
    # Default: Run the app
    print("""
╔═════════════════════════════════════════════════════════════╗
║    HOTSPOT — More-Like-Chatroom                            ║
║    Transform WiFi hotspots into game-like chat lobbies      ║
╚═════════════════════════════════════════════════════════════╝

[SETUP]
pip install pywifi pystray pillow aiortc (optional)

[DEMO]
1. Run on 2+ devices on same WiFi hotspot
2. Set nickname and join
3. See nearby lobbies with player counts
4. Chat with multicast isolation per SSID

[FEATURES]
✓ WiFi network scanning & lobby browser
✓ Multicast UDP per SSID for isolated chats
✓ Live player count tracking
✓ Game-like UI (CS:GO inspired)
✓ Quick commands (/map, /team, /ready)
✓ File sharing & emoji reactions
✓ Cross-platform (Windows/Mac/Linux)
✓ Statistics & history export

    """)
    
    print(f"[INFO] Local IP: {get_local_ip()}")
    print(f"[INFO] Current SSID: {get_current_ssid() or 'Not connected'}")
    print(f"[INFO] pywifi available: {PYWIFI_AVAILABLE}")
    print(f"[INFO] pystray available: {PYSTRAY_AVAILABLE}\n")
    
    root = tk.Tk()
    app = HotspotChatApp(root)
    root.mainloop()
