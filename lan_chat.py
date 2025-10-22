import socket
import threading
import tkinter as tk
import json
import sys
import winsound
import os
import uuid
import subprocess
import re
from datetime import datetime
from tkinter import messagebox

# TODO: maybe change port later if needed
PORT = 12345
BUFFER_SIZE = 1024
SECRET_KEY = 'MySecretChatKey2024'  # simple encryption key
is_running = True

# Colors I found online that look cool
BG_COLOR = "#0D1117"
GREEN_TEXT = "#00FF00"
BLUE_TEXT = "#1F6FEB"
DARK_INPUT = "#161B22"
BUTTON_COLOR = "#21262D"
RED_TEXT = "#FF6B6B"
BRIGHT_GREEN = "#39FF14"

# Simple encryption function I learned from stackoverflow
def encrypt_message(message, key):
    encrypted = ""
    for i in range(len(message)):
        encrypted += chr(ord(message[i]) ^ ord(key[i % len(key)]))
    return encrypted

# Same function works for decryption too (XOR magic!)
def decrypt_message(encrypted, key):
    return encrypt_message(encrypted, key)  # XOR is reversible

# Function to get my computer's IP address
def get_my_ip():
    try:
        # Connect to google DNS to find our IP
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_socket.connect(('8.8.8.8', 80))
        my_ip = temp_socket.getsockname()[0]
        temp_socket.close()
        return my_ip
    except:
        # If something goes wrong, use localhost
        return '127.0.0.1'

# Calculate broadcast IP for sending messages to everyone on network
def get_broadcast_address():
    my_ip = get_my_ip()
    parts = my_ip.split('.')
    # Replace last part with 255 for broadcast
    if len(parts) == 4:
        broadcast = parts[0] + '.' + parts[1] + '.' + parts[2] + '.255'
        return broadcast
    else:
        return '255.255.255.255'  # fallback

# Get MAC address - took me a while to figure this out
def get_mac_address():
    try:
        # Try using Windows command
        cmd_result = subprocess.run(['getmac', '/format', 'list'], 
                                  capture_output=True, text=True, timeout=5)
        if cmd_result.returncode == 0:
            lines = cmd_result.stdout.strip().split('\n')
            for line in lines:
                if 'Physical Address' in line and '=' in line:
                    mac_addr = line.split('=')[1].strip()
                    if mac_addr and mac_addr != 'N/A' and len(mac_addr) == 17:
                        # Convert format from AA-BB-CC to AA:BB:CC
                        return mac_addr.replace('-', ':').upper()
        
        # If that doesn't work, try this method I found online
        node = uuid.getnode()
        mac = ':'.join(re.findall('..', '%012x' % node))
        return mac.upper()
    except:
        # Just return something if all else fails
        return "00:00:00:00:00:00"

# This function doesn't work perfectly but I'll keep it for now
def find_mac_from_ip(ip_addr):
    try:
        arp_result = subprocess.run(['arp', '-a', ip_addr], 
                                  capture_output=True, text=True, timeout=3)
        if arp_result.returncode == 0:
            lines = arp_result.stdout.strip().split('\n')
            for line in lines:
                if ip_addr in line:
                    # Look for MAC pattern - this regex took forever to get right
                    mac_pattern = re.search(r'([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}', line)
                    if mac_pattern:
                        found_mac = mac_pattern.group(0).replace('-', ':').upper()
                        return found_mac
        return "Unknown"
    except:
        return "Unknown"

# Create the socket for network communication
def create_socket():
    try:
        # Create UDP socket
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow broadcasting
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Allow reusing address
        my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Set timeout so it doesn't hang forever
        my_socket.settimeout(1.0)
        # Bind to port
        my_socket.bind(('', PORT))
        return my_socket
    except Exception as e:
        print("ERROR: Could not create socket!")
        print("Error details:", e)
        print("Maybe try running as administrator?")
        return None

# Create the main socket
main_socket = create_socket()
if main_socket is None:
    print("Cannot start chat without network connection!")
    input("Press Enter to exit...")
    sys.exit(1)

# Main chat application class
class LanChatApp:
    def __init__(self, root):
        self.root = root
        self.my_ip = get_my_ip()
        self.broadcast_ip = get_broadcast_address()
        self.username = None
        self.connected = False
        self.sounds_on = True
        self.notifications_on = True
        self.my_id = str(uuid.uuid4())  # unique ID so I don't get my own messages
        self.message_history = set()  # to avoid duplicate messages
        self.my_mac = get_mac_address()
        
        print(f"My MAC address: {self.my_mac}")  # debug info
        
        
        # Setup the main window
        self.setup_window()
        
        # Start listening for messages
        message_thread = threading.Thread(target=self.listen_for_messages)
        message_thread.daemon = True
        message_thread.start()
    
    def setup_window(self):
        # Main window configuration
        self.root.title("My LAN Chat App")
        self.root.geometry("900x700")
        self.root.configure(bg=BG_COLOR)
        
        # Title section
        title_frame = tk.Frame(self.root, bg=BG_COLOR)
        title_frame.pack(fill="x", pady=10)
        
        title = tk.Label(title_frame, text="LAN Chat", 
                        bg=BG_COLOR, fg=BRIGHT_GREEN, 
                        font=("Consolas", 16, "bold"))
        title.pack()
        
        # Show connection info
        info_label = tk.Label(title_frame, 
                             text=f"Your IP: {self.my_ip} | Port: {PORT}",
                             bg=BG_COLOR, fg=BLUE_TEXT, 
                             font=("Consolas", 10))
        info_label.pack()
        
        
        # Username input area
        self.login_frame = tk.Frame(self.root, bg=BG_COLOR)
        self.login_frame.pack(fill="x", padx=10, pady=20)
        
        username_label = tk.Label(self.login_frame, 
                                 text="Enter your username:",
                                 bg=BG_COLOR, fg=GREEN_TEXT, 
                                 font=("Consolas", 12))
        username_label.pack(pady=10)
        
        self.username_input = tk.Entry(self.login_frame, 
                                      bg=DARK_INPUT, fg=GREEN_TEXT,
                                      font=("Consolas", 12), 
                                      insertbackground=GREEN_TEXT,
                                      relief="flat", bd=2)
        self.username_input.pack(pady=5, padx=20, fill="x")
        self.username_input.bind('<Return>', self.join_chat)
        
        join_btn = tk.Button(self.login_frame, text="JOIN CHAT",
                            bg=BUTTON_COLOR, fg=GREEN_TEXT,
                            font=("Consolas", 10, "bold"),
                            command=self.join_chat,
                            relief="flat", padx=20)
        join_btn.pack(pady=10)
        
        
        # Chat messages area
        self.chat_frame = tk.Frame(self.root, bg=BG_COLOR)
        
        # Scrollbar for chat
        chat_scrollbar = tk.Scrollbar(self.chat_frame, bg=BUTTON_COLOR, 
                                     troughcolor=BG_COLOR)
        chat_scrollbar.pack(side="right", fill="y")
        
        # Main chat display
        self.chat_area = tk.Text(self.chat_frame, bg=BG_COLOR, 
                                fg=GREEN_TEXT, font=("Consolas", 11),
                                state='disabled', 
                                insertbackground=GREEN_TEXT,
                                relief="flat", 
                                yscrollcommand=chat_scrollbar.set,
                                wrap="word")
        self.chat_area.pack(fill="both", expand=True)
        chat_scrollbar.config(command=self.chat_area.yview)
        
        # Message typing area
        self.message_frame = tk.Frame(self.root, bg=BG_COLOR)
        
        self.message_input = tk.Entry(self.message_frame, bg=DARK_INPUT, 
                                     fg=GREEN_TEXT, 
                                     font=("Consolas", 12),
                                     insertbackground=GREEN_TEXT,
                                     relief="flat", bd=2)
        self.message_input.pack(side="left", fill="x", expand=True, padx=5)
        self.message_input.bind('<Return>', self.send_message)
        
        send_btn = tk.Button(self.message_frame, text="SEND",
                            bg=BUTTON_COLOR, fg=GREEN_TEXT,
                            font=("Consolas", 10, "bold"),
                            command=self.send_message,
                            relief="flat", padx=15)
        send_btn.pack(side="right", padx=5)
        
        # Focus on username input initially
        self.username_input.focus_set()

    def join_chat(self, event=None):
        # Get username from input
        username = self.username_input.get().strip()
        
        # Basic validation
        if not username:
            self.show_error_popup("Please enter a username!")
            return
            
        if len(username) > 20:
            self.show_error_popup("Username too long! Keep it under 20 characters.")
            return
            
        # Check for weird characters that might break things
        bad_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        for char in bad_chars:
            if char in username:
                self.show_error_popup("Username has invalid characters!")
                return
                
        self.username = username
        self.connected = True
        
        # Hide login screen and show chat
        self.login_frame.pack_forget()
        self.chat_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.message_frame.pack(fill="x", padx=10, pady=10)
        
        self.root.title(f"LAN Chat - {self.username}")
        self.message_input.focus_set()
        
        # Tell everyone I joined
        join_message = {
            'type': 'join',
            'username': self.username,
            'ip': self.my_ip,
            'mac': self.my_mac,
            'id': self.my_id,
            'msg_id': str(uuid.uuid4())
        }
        self.broadcast_message(join_message)
        
        # Print to console for debugging
        print(f"Connected: {self.username}-{self.my_ip}-{self.my_mac}")
        self.add_message_to_chat("Welcome to LAN Chat!", BRIGHT_GREEN)

    def broadcast_message(self, message_data):
        # Send message to everyone on network
        try:
            # Convert to JSON
            json_string = json.dumps(message_data)
            # Encrypt it
            encrypted_data = encrypt_message(json_string, SECRET_KEY)
            # Send via UDP broadcast
            main_socket.sendto(encrypted_data.encode('utf-8'), 
                              (self.broadcast_ip, PORT))
        except Exception as e:
            print(f"Failed to send message: {e}")
            self.add_message_to_chat(f"Network error: {e}", RED_TEXT)
            self.show_error_popup(f"Could not send message: {e}")

    def listen_for_messages(self):
        # Keep listening for messages from other users
        global is_running
        while is_running:
            try:
                # Receive data from network
                received_data, sender_addr = main_socket.recvfrom(BUFFER_SIZE)
                
                # Skip if I'm not connected yet
                if not self.connected:
                    continue
                
                # Try to decrypt and parse the message
                try:
                    decrypted_data = decrypt_message(received_data.decode('utf-8'), SECRET_KEY)
                    message_obj = json.loads(decrypted_data)
                except:
                    continue  # Skip if message is corrupted
                
                # Don't process my own messages
                if message_obj.get('id') == self.my_id:
                    continue
                
                # Avoid duplicate messages
                msg_id = message_obj.get('msg_id')
                if msg_id and msg_id in self.message_history:
                    continue
                
                # Remember this message ID
                if msg_id:
                    self.message_history.add(msg_id)
                    # Keep only recent messages to save memory
                    if len(self.message_history) > 100:
                        # Remove some old ones (not the best way but works)
                        old_messages = list(self.message_history)
                        self.message_history = set(old_messages[-50:])
                
                # Handle different message types
                if message_obj.get('type') == 'join':
                    user = message_obj.get('username', 'Someone')
                    user_ip = message_obj.get('ip', 'Unknown')
                    user_mac = message_obj.get('mac', 'Unknown')
                    
                    # Show in chat
                    self.add_message_to_chat(f"{user} joined the chat!", BRIGHT_GREEN)
                    
                    # Print to console
                    print(f"Device Connected: {user}-{user_ip}-{user_mac}")
                    
                    # Play sound and show notification
                    self.play_sound('join')
                    self.show_popup_notification(f"{user} joined")
                    
                elif message_obj.get('type') == 'leave':
                    user = message_obj.get('username', 'Someone')
                    user_ip = message_obj.get('ip', 'Unknown')
                    user_mac = message_obj.get('mac', 'Unknown')
                    
                    # Show in chat
                    self.add_message_to_chat(f"{user} left the chat", RED_TEXT)
                    
                    # Print to console
                    print(f"Device Disconnected: {user}-{user_ip}-{user_mac}")
                    
                    self.play_sound('leave')
                    
                elif message_obj.get('type') == 'chat':
                    sender = message_obj.get('username', 'Unknown')
                    text = message_obj.get('text', '')
                    
                    # Display the message
                    self.add_message_to_chat(f"{sender}: {text}", GREEN_TEXT)
                    self.play_sound('message')
                    self.show_popup_notification(f"New message from {sender}")
                    self.blink_window()
                    
            except socket.timeout:
                continue  # This is normal, just keep trying
            except Exception as e:
                if is_running and self.connected:
                    print(f"Error receiving message: {e}")
                    self.add_message_to_chat(f"Network error: {e}", RED_TEXT)

    def add_message_to_chat(self, message, color):
        # Add a message to the chat display with timestamp
        def update_chat():
            self.chat_area.config(state='normal')
            
            # Get current time
            current_time = datetime.now().strftime('%H:%M:%S')
            formatted_message = f"[{current_time}] {message}\n"
            
            # Add to chat
            self.chat_area.insert(tk.END, formatted_message)
            self.chat_area.tag_add("msg_color", "end-2l", "end-1l")
            self.chat_area.tag_config("msg_color", foreground=color)
            
            # Make it read-only again
            self.chat_area.config(state='disabled')
            # Auto scroll to bottom
            self.chat_area.see(tk.END)
        
        # Update GUI from main thread
        self.root.after(0, update_chat)

    def send_message(self, event=None):
        # Send a message to everyone
        message_text = self.message_input.get().strip()
        
        if not message_text:
            return  # Don't send empty messages
            
        if len(message_text) > 500:
            self.show_error_popup("Message is too long! Keep it under 500 characters.")
            return
            
        # Check if it's a command
        if message_text.startswith('/'):
            self.process_command(message_text)
        else:
            # Create message object
            msg_id = str(uuid.uuid4())
            chat_message = {
                'type': 'chat',
                'username': self.username,
                'text': message_text,
                'ip': self.my_ip,
                'mac': self.my_mac,
                'id': self.my_id,
                'msg_id': msg_id
            }
            
            # Remember this message so I don't receive it back
            self.message_history.add(msg_id)
            
            # Send to network
            self.broadcast_message(chat_message)
            
            # Show in my own chat
            self.add_message_to_chat(f"You: {message_text}", BLUE_TEXT)
        
        # Clear input box
        self.message_input.delete(0, tk.END)

    def process_command(self, command_text):
        # Handle special commands
        cmd = command_text.lower()
        
        if cmd == '/clear':
            # Clear the chat window
            self.chat_area.config(state='normal')
            self.chat_area.delete(1.0, tk.END)
            self.chat_area.config(state='disabled')
            self.add_message_to_chat("Chat cleared!", BRIGHT_GREEN)
            
        elif cmd == '/help':
            # Show help
            help_msg = "Commands:\n/help - Show this help\n/clear - Clear chat window"
            self.add_message_to_chat(help_msg, BRIGHT_GREEN)
            
        else:
            # Unknown command
            self.add_message_to_chat(f"Unknown command: {command_text}. Type /help for help.", RED_TEXT)

    def play_sound(self, sound_type):
        # Play different sounds for different events
        if not self.sounds_on:
            return
            
        try:
            if sound_type == 'join' or sound_type == 'leave':
                winsound.Beep(800, 200)  # High beep
            elif sound_type == 'message':
                winsound.Beep(600, 150)  # Medium beep
            elif sound_type == 'error':
                winsound.Beep(400, 300)  # Low beep
        except:
            # If beep doesn't work, try system sound
            try:
                winsound.MessageBeep(winsound.MB_OK)
            except:
                pass  # Give up if no sound works

    def show_popup_notification(self, message):
        # Show a popup notification (basic version)
        if not self.notifications_on:
            return
            
        try:
            # Bring window to front if it's not focused
            if not self.root.focus_get():
                self.root.attributes('-topmost', True)
                self.root.after(100, lambda: self.root.attributes('-topmost', False))
        except:
            pass

    def blink_window(self):
        # Make window title blink to show new message
        if not self.notifications_on:
            return
            
        try:
            old_title = self.root.title()
            self.root.title("*** NEW MESSAGE *** " + old_title)
            # Change back after 2 seconds
            self.root.after(2000, lambda: self.root.title(old_title))
        except:
            pass

    def show_error_popup(self, error_message):
        # Show error dialog
        self.play_sound('error')
        messagebox.showerror("Error", error_message)



    def cleanup_and_exit(self):
        # Clean up when user closes the window
        global is_running
        is_running = False
        
        # Tell everyone I'm leaving
        if self.connected:
            try:
                goodbye_message = {
                    'type': 'leave',
                    'username': self.username,
                    'ip': self.my_ip,
                    'mac': self.my_mac,
                    'id': self.my_id,
                    'msg_id': str(uuid.uuid4())
                }
                self.broadcast_message(goodbye_message)
            except:
                pass  # Don't worry if this fails
        
        # Close socket
        try:
            main_socket.close()
        except:
            pass
        
        # Close window
        self.root.destroy()

# Main program starts here
if __name__ == "__main__":
    print("=== My LAN Chat Application ===")
    print(f"Your IP address: {get_my_ip()}")
    print(f"Using port: {PORT}")
    print("Starting chat application...")
    
    # Create the GUI
    root_window = tk.Tk()
    chat_app = LanChatApp(root_window)
    
    # Handle window closing
    root_window.protocol("WM_DELETE_WINDOW", chat_app.cleanup_and_exit)
    
    # Start the GUI
    root_window.mainloop()
    
    print("Chat application closed. Goodbye!")
