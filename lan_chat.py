import socket
import threading
import tkinter as tk
import json
import sys
from datetime import datetime
from tkinter import ttk

# Configuration
PORT = 12345
BUFFER_SIZE = 1024
XOR_KEY = 'SimpleChatKey123'
running = True

# Color scheme - terminal-inspired
BACKGROUND = "#0D1117"
TEXT_COLOR = "#00FF00"
ACCENT_COLOR = "#1F6FEB"
INPUT_BG = "#161B22"
BUTTON_BG = "#21262D"
ERROR_COLOR = "#FF6B6B"
SUCCESS_COLOR = "#39FF14"

def xor_encrypt_decrypt(data, key):
    """Simple XOR encryption for basic message obfuscation"""
    result = ""
    for i, char in enumerate(data):
        result += chr(ord(char) ^ ord(key[i % len(key)]))
    return result

def get_local_ip():
    """Get the local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return '127.0.0.1'

def get_broadcast_ip():
    """Calculate broadcast address from local IP"""
    ip_parts = get_local_ip().split('.')
    if len(ip_parts) == 4:
        return '.'.join(ip_parts[:-1] + ['255'])
    return '255.255.255.255'

# Setup UDP socket for broadcasting
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(1.0)
    sock.bind(('', PORT))
except Exception as e:
    print(f"Failed to setup network: {e}")
    sys.exit(1)

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.local_ip = get_local_ip()
        self.broadcast_ip = get_broadcast_ip()
        self.nickname = None
        self.nickname_set = False
        
        # Window setup
        root.title("LAN Chat")
        root.geometry("900x700")
        root.configure(bg=BACKGROUND)
        
        # Header
        header_frame = tk.Frame(root, bg=BACKGROUND)
        header_frame.pack(fill="x", pady=10)
        
        title_label = tk.Label(header_frame, text="LAN Chat", 
                              bg=BACKGROUND, fg=SUCCESS_COLOR, 
                              font=("Consolas", 16, "bold"))
        title_label.pack()
        
        connection_label = tk.Label(header_frame, 
                                   text=f"Connected to {self.local_ip}:{PORT}",
                                   bg=BACKGROUND, fg=ACCENT_COLOR, 
                                   font=("Consolas", 10))
        connection_label.pack()
        
        # Nickname input section
        self.nickname_frame = tk.Frame(root, bg=BACKGROUND)
        self.nickname_frame.pack(fill="x", padx=10, pady=20)
        
        nickname_label = tk.Label(self.nickname_frame, 
                                 text="Enter your nickname:",
                                 bg=BACKGROUND, fg=TEXT_COLOR, 
                                 font=("Consolas", 12))
        nickname_label.pack(pady=10)
        
        self.nickname_entry = tk.Entry(self.nickname_frame, 
                                      bg=INPUT_BG, fg=TEXT_COLOR,
                                      font=("Consolas", 12), 
                                      insertbackground=TEXT_COLOR,
                                      relief="flat", bd=2)
        self.nickname_entry.pack(pady=5, padx=20, fill="x")
        self.nickname_entry.bind('<Return>', self.set_nickname)
        
        join_button = tk.Button(self.nickname_frame, text="JOIN CHAT",
                               bg=BUTTON_BG, fg=TEXT_COLOR,
                               font=("Consolas", 10, "bold"),
                               command=self.set_nickname,
                               relief="flat", padx=20)
        join_button.pack(pady=10)
        
        # Chat display area
        self.chat_frame = tk.Frame(root, bg=BACKGROUND)
        
        scrollbar = tk.Scrollbar(self.chat_frame, bg=BUTTON_BG, 
                                troughcolor=BACKGROUND)
        scrollbar.pack(side="right", fill="y")
        
        self.chat_display = tk.Text(self.chat_frame, bg=BACKGROUND, 
                                   fg=TEXT_COLOR, font=("Consolas", 11),
                                   state='disabled', 
                                   insertbackground=TEXT_COLOR,
                                   relief="flat", 
                                   yscrollcommand=scrollbar.set,
                                   wrap="word")
        self.chat_display.pack(fill="both", expand=True)
        scrollbar.config(command=self.chat_display.yview)
        
        # Message input area
        self.input_frame = tk.Frame(root, bg=BACKGROUND)
        
        self.message_entry = tk.Entry(self.input_frame, bg=INPUT_BG, 
                                     fg=TEXT_COLOR, 
                                     font=("Consolas", 12),
                                     insertbackground=TEXT_COLOR,
                                     relief="flat", bd=2)
        self.message_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.message_entry.bind('<Return>', self.send_message)
        
        send_button = tk.Button(self.input_frame, text="SEND",
                               bg=BUTTON_BG, fg=TEXT_COLOR,
                               font=("Consolas", 10, "bold"),
                               command=self.send_message,
                               relief="flat", padx=15)
        send_button.pack(side="right", padx=5)
        
        self.nickname_entry.focus_set()
        
        # Start receiving messages in background
        receive_thread = threading.Thread(target=self.receive_messages, 
                                         daemon=True)
        receive_thread.start()

    def set_nickname(self, event=None):
        """Set user nickname and join the chat"""
        nickname = self.nickname_entry.get().strip()
        if nickname:
            self.nickname = nickname
            self.nickname_set = True
            
            # Hide nickname input, show chat interface
            self.nickname_frame.pack_forget()
            self.chat_frame.pack(fill="both", expand=True, padx=10, pady=5)
            self.input_frame.pack(fill="x", padx=10, pady=10)
            
            self.root.title(f"LAN Chat - {self.nickname}")
            self.message_entry.focus_set()
            
            # Broadcast join message
            join_data = {
                'type': 'join',
                'nickname': self.nickname,
                'ip': self.local_ip
            }
            self.send_data(join_data)

    def send_data(self, message):
        """Encrypt and broadcast message to network"""
        try:
            json_data = json.dumps(message)
            encrypted = xor_encrypt_decrypt(json_data, XOR_KEY)
            sock.sendto(encrypted.encode('utf-8'), 
                       (self.broadcast_ip, PORT))
        except Exception as e:
            self.display_message(f"Send error: {e}", ERROR_COLOR)

    def receive_messages(self):
        """Listen for incoming messages"""
        while running:
            try:
                data, addr = sock.recvfrom(BUFFER_SIZE)
                
                # Ignore own messages
                if addr[0] == self.local_ip or not self.nickname_set:
                    continue
                
                # Decrypt and parse message
                decrypted = xor_encrypt_decrypt(data.decode('utf-8'), XOR_KEY)
                message = json.loads(decrypted)
                
                if message['type'] == 'join':
                    join_text = f"{message['nickname']} JOINED"
                    self.display_message(join_text, SUCCESS_COLOR)
                    
                elif message['type'] == 'message':
                    chat_text = f"{message['nickname']}: {message['message']}"
                    self.display_message(chat_text, TEXT_COLOR)
                    
            except socket.timeout:
                continue
            except Exception as e:
                if running and self.nickname_set:
                    self.display_message(f"Error: {e}", ERROR_COLOR)

    def display_message(self, message, color):
        """Display message in chat window with timestamp"""
        def update_display():
            self.chat_display.config(state='normal')
            
            timestamp = datetime.now().strftime('%H:%M:%S')
            full_message = f"[{timestamp}] {message}\n"
            
            self.chat_display.insert(tk.END, full_message)
            self.chat_display.tag_add("color", "end-2l", "end-1l")
            self.chat_display.tag_config("color", foreground=color)
            
            self.chat_display.config(state='disabled')
            self.chat_display.see(tk.END)
        
        self.root.after(0, update_display)

    def send_message(self, event=None):
        """Send message or handle commands"""
        text = self.message_entry.get().strip()
        if text:
            if text.startswith('/'):
                self.handle_command(text)
            else:
                message_data = {
                    'type': 'message',
                    'nickname': self.nickname,
                    'message': text,
                    'ip': self.local_ip
                }
                self.send_data(message_data)
                self.display_message(f"You: {text}", ACCENT_COLOR)
            
            self.message_entry.delete(0, tk.END)

    def handle_command(self, text):
        """Process chat commands"""
        if text == '/clear':
            self.chat_display.config(state='normal')
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.config(state='disabled')
            
        elif text == '/help':
            help_text = "Available commands: /help, /clear"
            self.display_message(help_text, SUCCESS_COLOR)
            
        else:
            self.display_message(f"Unknown command: {text}", ERROR_COLOR)

    def on_closing(self):
        """Clean up when closing the application"""
        global running
        running = False
        
        try:
            sock.close()
        except:
            pass
        
        self.root.destroy()

if __name__ == "__main__":
    print(f"Your IP: {get_local_ip()}")
    print(f"Port: {PORT}")
    root = tk.Tk()
    app = ChatApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()