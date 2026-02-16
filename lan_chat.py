





import socket
import threading
import tkinter as tk
import json
import sys
import sys
import os
import uuid
import math
import struct
import tempfile
import subprocess
try:
    import winsound
except ImportError:
    winsound = None
from datetime import datetime
from tkinter import ttk, messagebox, filedialog

# Configuration
PORT = 12345
BUFFER_SIZE = 4096  # Increased buffer size for larger messages if needed
FILE_BUFFER_SIZE = 8192
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
        # Try to connect to a public DNS provider
        try:
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
        except:
            # Fallback: try to connect to a private address (doesn't need to be reachable)
            # This helps pick the main interface on some systems
            s.connect(('10.255.255.255', 1))
            local_ip = s.getsockname()[0]
        finally:
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
def setup_socket():
    """Setup and configure the UDP socket"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)
        sock.bind(('', PORT))
        return sock
    except socket.error as e:
        print(f"Network setup failed: {e}")
        print("This might be due to:")
        print("- Port already in use")
        print("- Firewall blocking the connection")
        print("- Network adapter issues")
        return None
    except Exception as e:
        print(f"Unexpected error during network setup: {e}")
        return None

sock = setup_socket()
if sock is None:
    print("Failed to initialize network. Exiting...")
    sys.exit(1)

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.local_ip = get_local_ip()
        self.broadcast_ip = get_broadcast_ip()
        self.nickname = None
        self.nickname_set = False
        self.sound_enabled = True
        self.notifications_enabled = True
        self.client_id = str(uuid.uuid4())  # Unique identifier for this client
        self.sent_messages = set()  # Track sent message IDs to avoid duplicates
        self.is_focused = True
        
        # Window setup
        root.title("LAN Chat")
        root.geometry("900x700")
        root.configure(bg=BACKGROUND)
        
        # Focus binding
        root.bind("<FocusIn>", self.on_focus_in)
        root.bind("<FocusOut>", self.on_focus_out)
        
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
        
        self.message_entry = tk.Text(self.input_frame, bg=INPUT_BG, 
                                     fg=TEXT_COLOR, 
                                     font=("Consolas", 12),
                                     insertbackground=TEXT_COLOR,
                                     relief="flat", bd=2,
                                     height=3)
        self.message_entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        self.message_entry.bind('<Return>', self.handle_return)
        self.message_entry.bind('<Shift-Return>', self.handle_shift_return)
        
        send_button = tk.Button(self.input_frame, text="SEND",
                               bg=BUTTON_BG, fg=TEXT_COLOR,
                               font=("Consolas", 10, "bold"),
                               command=self.send_message,
                               relief="flat", padx=15)
        send_button.pack(side="right", padx=5)
        
        file_button = tk.Button(self.input_frame, text="FILE",
                               bg=BUTTON_BG, fg=ACCENT_COLOR,
                               font=("Consolas", 10, "bold"),
                               command=self.send_file_action,
                               relief="flat", padx=15)
        file_button.pack(side="right", padx=5)
        
        self.nickname_entry.focus_set()
        
        # Start receiving messages in background
        receive_thread = threading.Thread(target=self.receive_messages, 
                                         daemon=True)
        receive_thread.start()

    def set_nickname(self, event=None):
        """Set user nickname and join the chat"""
        nickname = self.nickname_entry.get().strip()
        if not nickname:
            self.show_error("Please enter a nickname!")
            return
            
        if len(nickname) > 20:
            self.show_error("Nickname must be 20 characters or less!")
            return
            
        # Check for invalid characters
        invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        if any(char in nickname for char in invalid_chars):
            self.show_error("Nickname contains invalid characters!")
            return
            
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
            'ip': self.local_ip,
            'client_id': self.client_id,
            'message_id': str(uuid.uuid4())
        }
        self.send_data(join_data)
        self.display_message("Connected to LAN Chat!", SUCCESS_COLOR)

    def send_data(self, message):
        """Encrypt and broadcast message to network"""
        try:
            json_data = json.dumps(message)
            encrypted = xor_encrypt_decrypt(json_data, XOR_KEY)
            sock.sendto(encrypted.encode('utf-8'), 
                       (self.broadcast_ip, PORT))
        except socket.error as e:
            self.display_message(f"Network error: {e}", ERROR_COLOR)
            self.show_error(f"Failed to send message: {e}")
        except Exception as e:
            self.display_message(f"Send error: {e}", ERROR_COLOR)
            self.show_error(f"Unexpected error: {e}")

    def receive_messages(self):
        """Listen for incoming messages"""
        while running:
            try:
                data, addr = sock.recvfrom(BUFFER_SIZE)
                
                # Skip if not connected yet
                if not self.nickname_set:
                    continue
                
                # Decrypt and parse message
                try:
                    decrypted = xor_encrypt_decrypt(data.decode('utf-8'), XOR_KEY)
                    message = json.loads(decrypted)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue  # Skip malformed messages
                
                # Ignore messages from this client (using client_id)
                if message.get('client_id') == self.client_id:
                    continue
                
                # Check for duplicate messages using message_id
                message_id = message.get('message_id')
                if message_id and message_id in self.sent_messages:
                    continue
                
                # Add message_id to tracking set (keep only last 100 to prevent memory issues)
                if message_id:
                    self.sent_messages.add(message_id)
                    if len(self.sent_messages) > 100:
                        # Remove oldest entries (this is a simple approach)
                        self.sent_messages = set(list(self.sent_messages)[-50:])
                
                if message.get('type') == 'join':
                    join_text = f"{message.get('nickname', 'Unknown')} JOINED"
                    self.display_message(join_text, SUCCESS_COLOR)
                    self.play_notification_sound('join')
                    self.show_notification(f"{message.get('nickname', 'Someone')} joined the chat")
                    
                elif message.get('type') == 'file_offer':
                    nick = message.get('nickname', 'Unknown')
                    fname = message.get('filename', '?')
                    fsize = message.get('filesize', 0)
                    ip = message.get('ip')
                    port = message.get('tcp_port')
                    
                    self.display_file_offer(nick, fname, fsize, ip, port)
                    self.play_notification_sound('message')
                    self.show_notification(f"{nick} shared a file: {fname}")
                    self.flash_window()
                    
                elif message.get('type') == 'leave':
                    leave_text = f"{message.get('nickname', 'Unknown')} LEFT"
                    self.display_message(leave_text, ERROR_COLOR)
                    self.play_notification_sound('leave')
                    self.show_notification(f"{message.get('nickname', 'Unknown')} left the chat")
                    
                elif message.get('type') == 'message':
                    nickname = message.get('nickname', 'Unknown')
                    msg_text = message.get('message', '')
                    chat_text = f"{nickname}: {msg_text}"
                    self.display_message(chat_text, TEXT_COLOR)
                    self.play_notification_sound('message')
                    self.show_notification(f"New message from {nickname}")
                    self.flash_window()
                    
            except socket.timeout:
                continue
            except socket.error as e:
                if running and self.nickname_set:
                    self.display_message(f"Network error: {e}", ERROR_COLOR)
            except Exception as e:
                if running and self.nickname_set:
                    self.display_message(f"Receive error: {e}", ERROR_COLOR)

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

    def handle_return(self, event):
        """Handle Enter key to send message"""
        if not event.state & 0x1: # Check if Shift is not pressed
            self.send_message()
            return "break" # Prevent newline insertion
            
    def handle_shift_return(self, event):
        """Handle Shift+Enter to insert newline"""
        return # Allow default behavior

    def send_message(self, event=None):
        """Send message or handle commands"""
        text = self.message_entry.get("1.0", tk.END).strip()
        if not text:
            return
            
        if len(text) > 3000:
            self.show_error("Message too long! Maximum 3000 characters.")
            return
            
        if text.startswith('/'):
            self.handle_command(text)
        else:
            message_id = str(uuid.uuid4())
            message_data = {
                'type': 'message',
                'nickname': self.nickname,
                'message': text,
                'ip': self.local_ip,
                'client_id': self.client_id,
                'message_id': message_id
            }
            # Track this message ID to avoid receiving our own message
            self.sent_messages.add(message_id)
            self.send_data(message_data)
            self.display_message(f"You: {text}", ACCENT_COLOR)
        
            self.display_message(f"You: {text}", ACCENT_COLOR)
        
        self.message_entry.delete("1.0", tk.END)

    def handle_command(self, text):
        """Process chat commands"""
        command = text.lower()
        
        if command == '/clear':
            self.chat_display.config(state='normal')
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.config(state='disabled')
            self.display_message("Chat cleared", SUCCESS_COLOR)
            
        elif command == '/help':
            help_text = "Available commands:\n/help - Show this help\n/clear - Clear chat"
            self.display_message(help_text, SUCCESS_COLOR)
            
        else:
            self.display_message(f"Unknown command: {text}. Type /help for available commands.", ERROR_COLOR)


    def on_focus_in(self, event):
        self.is_focused = True

    def on_focus_out(self, event):
        self.is_focused = False

    def play_sound_cross_platform(self, frequency, duration):
        """Play sound on Windows or Linux with threading and fallback"""
        def _play():
            try:
                # Ensure integer types
                freq = int(frequency)
                dur = int(duration)
                
                if winsound:
                    try:
                        winsound.Beep(freq, dur)
                    except Exception as e:
                        print(f"DEBUG: winsound.Beep failed: {e}")
                        # Fallback to system beep
                        try:
                            winsound.MessageBeep(winsound.MB_OK)
                        except:
                            pass
                else:
                    # Linux/Mac fallback (existing logic)
                    try:
                        sample_rate = 44100
                        n_samples = int(sample_rate * (dur / 1000.0))
                        
                        audio = []
                        for i in range(n_samples):
                            value = int(32767.0 * 0.5 * math.sin(2.0 * math.pi * freq * i / sample_rate))
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
                            subprocess.run(['aplay', '-q', tmp_name], check=False)
                        except FileNotFoundError:
                            try:
                                subprocess.run(['paplay', tmp_name], check=False)
                            except FileNotFoundError:
                                pass
                        
                        try:
                            os.remove(tmp_name)
                        except:
                            pass
                    except Exception:
                        pass
            except Exception as e:
                 print(f"DEBUG: Sound playback error: {e}")

        # Run sound in a separate thread to avoid blocking
        threading.Thread(target=_play, daemon=True).start()

    def play_notification_sound(self, sound_type='message'):
        """Play notification sound based on type and window focus"""
        if not self.sound_enabled:
            return
            
        try:
            if sound_type == 'join':
                # Join sound - Medium high
                self.play_sound_cross_platform(1000, 150)
            elif sound_type == 'leave':
                 # Leave sound - Lower pitch, slightly longer
                 self.play_sound_cross_platform(600, 300)
            elif sound_type == 'error':
                 self.play_sound_cross_platform(300, 300)
            elif sound_type == 'message':
                if self.is_focused:
                    # Active - High Pitch (Active)
                    self.play_sound_cross_platform(1200, 150)
                else:
                    # Inactive - Low Pitch (Inactive)
                    self.play_sound_cross_platform(300, 300)
        except Exception:
            pass

    def show_notification(self, message):
        """Show visual notification"""
        if not self.notifications_enabled:
            return
            
        # Flash the taskbar if window is not focused
        try:
            if not self.root.focus_get():
                self.root.attributes('-topmost', True)
                self.root.after(100, lambda: self.root.attributes('-topmost', False))
        except Exception:
            pass

    def flash_window(self):
        """Flash the window to get attention"""
        if not self.notifications_enabled:
            return
            
        try:
            # Change title briefly to indicate new message
            original_title = self.root.title()
            self.root.title("*** NEW MESSAGE *** " + original_title)
            self.root.after(2000, lambda: self.root.title(original_title))
        except Exception:
            pass

    def show_error(self, message):
        """Show error dialog and play error sound"""
        self.play_notification_sound('error')
        messagebox.showerror("Error", message)



    def send_file_action(self):
        """Handle file selection and offering"""
        filename = filedialog.askopenfilename()
        if not filename:
            return
            
        # Start server in a thread
        try:
            # Create a TCP socket for this file
            file_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            file_sock.bind(('0.0.0.0', 0)) # Explicitly bind to all interfaces
            port = file_sock.getsockname()[1]
            file_sock.listen(5)
            
            file_size = os.path.getsize(filename)
            file_basename = os.path.basename(filename)
            
            # Start the server thread
            threading.Thread(target=self.file_server_thread, 
                           args=(file_sock, filename), daemon=True).start()
            
            # Broadcast offer
            offer_id = str(uuid.uuid4())
            offer_data = {
                'type': 'file_offer',
                'nickname': self.nickname,
                'filename': file_basename,
                'filesize': file_size,
                'ip': self.local_ip,
                'tcp_port': port,
                'client_id': self.client_id,
                'message_id': offer_id
            }
            self.send_data(offer_data)
            self.sent_messages.add(offer_id)
            
            self.display_message(f"You offered file: {file_basename} ({self.format_size(file_size)})", ACCENT_COLOR)
            
        except Exception as e:
            self.show_error(f"Failed to start file share: {e}")

    def file_server_thread(self, sock, filepath):
        """Serve the file to connecting clients"""
        try:
            # Serve for a limited time or until app closes
            # For simplicity, we just loop forever in this daemon thread
            # In a real app, you might want a timeout or management
            while running:
                client, addr = sock.accept()
                threading.Thread(target=self.handle_file_client, 
                               args=(client, filepath), daemon=True).start()
        except:
            pass
        finally:
            try:
                sock.close()
            except:
                pass

    def handle_file_client(self, client_sock, filepath):
        """Send file data to a single client"""
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

    def display_file_offer(self, nickname, filename, filesize, ip, port):
        """Display a file offer with a download button"""
        def update_ui():
            self.chat_display.config(state='normal')
            timestamp = datetime.now().strftime('%H:%M:%S')
            
            # Header
            header = f"[{timestamp}] {nickname} is sharing a file:\n"
            self.chat_display.insert(tk.END, header)
            
            # File info
            info = f"  {filename} ({self.format_size(filesize)})  "
            self.chat_display.insert(tk.END, info)
            
             # Download button
            btn = tk.Button(self.chat_display, text="DOWNLOAD", 
                           font=("Consolas", 8, "bold"),
                           bg=ACCENT_COLOR, fg="white",
                           cursor="hand2")
            # Configure command separately to pass button reference
            btn.configure(command=lambda b=btn: self.start_download(filename, filesize, ip, port, b))
            
            self.chat_display.window_create(tk.END, window=btn)
            self.chat_display.insert(tk.END, "\n")
            
            self.chat_display.config(state='disabled')
            self.chat_display.see(tk.END)
            
        self.root.after(0, update_ui)

    def start_download(self, filename, filesize, ip, port, btn):
        """Start file download process"""
        try:
            save_path = filedialog.asksaveasfilename(initialfile=filename)
        except Exception as e:
            print(f"File dialog error: {e}")
            return
            
        if not save_path:
            return
        
        btn.config(state='disabled', text="Starting...", bg=BUTTON_BG)
            
        threading.Thread(target=self.download_thread, 
                       args=(save_path, filesize, ip, port, btn), daemon=True).start()

    def download_thread(self, save_path, filesize, ip, port, btn):
        """Execute download in background"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10) # Connect timeout
            s.connect((ip, port))
            
            received = 0
            last_update_time = 0
            
            with open(save_path, 'wb') as f:
                while True:
                    data = s.recv(FILE_BUFFER_SIZE)
                    if not data:
                        break
                    f.write(data)
                    received += len(data)
                    
                    # Update progress every 100ms or so to avoid overwhelming UI thread
                    current_time = datetime.now().timestamp()
                    if current_time - last_update_time > 0.1:
                        percent = int((received / filesize) * 100) if filesize > 0 else 0
                        self.root.after(0, lambda p=percent: btn.config(text=f"{p}%"))
                        last_update_time = current_time
            
            s.close()
            
            if received == filesize:
                self.root.after(0, lambda: btn.config(text="OPEN", bg=SUCCESS_COLOR, state='normal', 
                                                     command=lambda: self.open_file(save_path)))
                self.root.after(0, lambda: messagebox.showinfo("Download Complete", 
                                                             f"File saved to:\n{save_path}"))
            else:
                self.root.after(0, lambda: self.show_error(
                    f"Download incomplete.\nReceived {self.format_size(received)} of {self.format_size(filesize)}"))
                self.root.after(0, lambda: btn.config(text="RETRY", state='normal', bg=ERROR_COLOR))
                
        except Exception as e:
            print(f"Download thread error: {e}") # Console log for debug
            error_msg = f"Download failed: {e}"
            self.root.after(0, lambda: self.show_error(error_msg))
            self.root.after(0, lambda: btn.config(text="ERROR", bg=ERROR_COLOR))

    def open_file(self, filepath):
        """Open the downloaded file"""
        try:
            if sys.platform == 'win32':
                os.startfile(filepath)
            elif sys.platform == 'darwin':
                subprocess.call(('open', filepath))
            else:
                subprocess.call(('xdg-open', filepath))
        except Exception as e:
            print(f"Open file error: {e}")
            self.show_error(f"Could not open file: {e}\nLocation: {filepath}")

    def format_size(self, size):
        """Format bytes to human readable string"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def on_closing(self):
        """Clean up when closing the application"""
        global running
        running = False 
        if self.nickname_set:
            try:
                leave_data = {
                    'nickname': self.nickname,
                    'ip': self.local_ip,
                    'client_id': self.client_id,
                    'message_id': str(uuid.uuid4())
                }
                self.send_data(leave_data)
            except Exception:
                pass
        
        try:
            sock.close()
        except Exception:
            pass
        
        self.root.destroy()
    
if __name__ == "__main__":
    print(f"Your IP: {get_local_ip()}")
    print(f"Port: {PORT}")
    root = tk.Tk()
    app = ChatApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()



