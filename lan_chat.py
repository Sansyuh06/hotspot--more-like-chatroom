import socket, threading, tkinter as tk, json, sys, winsound, os, uuid, subprocess, re, base64
from datetime import datetime
from tkinter import messagebox

PORT = 12345
BUF = 4096
KEY = "MySecretChatKey2024"
is_running = True

BG = "#0D1117"
TXT = "#00FF00"
TXT2 = "#1F6FEB"
INP = "#161B22"
BTN = "#21262D"
ERR = "#FF6B6B"
BRG = "#39FF14"

def _xor_bytes(b1, b2):
    out = bytearray(len(b1))
    k = len(b2)
    for i, x in enumerate(b1):
        out[i] = x ^ b2[i % k]
    return bytes(out)

def encrypt_message(msg, key):
    try:
        x = _xor_bytes(msg.encode(), key.encode())
        return base64.b64encode(x).decode()
    except:
        return base64.b64encode(msg.encode()).decode()

def decrypt_message(enc, key):
    try:
        raw = base64.b64decode(enc)
        d = _xor_bytes(raw, key.encode())
        return d.decode(errors="replace")
    except:
        try:
            return base64.b64decode(enc).decode(errors="replace")
        except:
            return ""

def get_my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_broadcast():
    p = get_my_ip().split(".")
    return f"{p[0]}.{p[1]}.{p[2]}.255" if len(p)==4 else "255.255.255.255"

def get_mac():
    try:
        out = subprocess.run(["getmac","/format","list"],capture_output=True,text=True,timeout=4)
        if out.returncode==0:
            for ln in out.stdout.splitlines():
                if "Physical Address" in ln and "=" in ln:
                    m = ln.split("=")[1].strip()
                    if m and m!="N/A":
                        return m.replace("-" ,":").upper()
        n = uuid.getnode()
        return ":".join(re.findall("..", "%012x" % n)).upper()
    except:
        return "00:00:00:00:00:00"

def sock():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(1)
        s.bind(("", PORT))
        return s
    except:
        return None

main_sock = sock()
if not main_sock:
    print("Socket fail")
    input()
    sys.exit(1)

class LanChatApp:
    def __init__(self, root):
        self.root = root
        self.my_ip = get_my_ip()
        self.bc = get_broadcast()
        self.username = None
        self.connected = False
        self.sounds = True
        self.notifs = True
        self.my_id = str(uuid.uuid4())
        self.hist = set()
        self.my_mac = get_mac()

        self._ui()
        threading.Thread(target=self._listen, daemon=True).start()

    def _ui(self):
        r = self.root
        r.title("LAN Chat")
        r.geometry("900x700")
        r.configure(bg=BG)

        top = tk.Frame(r, bg=BG); top.pack(fill="x", pady=8)
        tk.Label(top, text="LAN Chat", bg=BG, fg=BRG, font=("Consolas",16,"bold")).pack()
        tk.Label(top, text=f"{self.my_ip}:{PORT}", bg=BG, fg=TXT2, font=("Consolas",10)).pack()

        self.logf = tk.Frame(r, bg=BG); self.logf.pack(fill="x", padx=10, pady=15)
        tk.Label(self.logf, text="Username:", bg=BG, fg=TXT, font=("Consolas",12)).pack(pady=6)
        self.user_in = tk.Entry(self.logf, bg=INP, fg=TXT, font=("Consolas",12), insertbackground=TXT, relief="flat")
        self.user_in.pack(pady=4, padx=20, fill="x")
        self.user_in.bind("<Return>", self.join_chat)
        tk.Button(self.logf, text="JOIN", bg=BTN, fg=TXT, font=("Consolas",10,"bold"), command=self.join_chat, relief="flat").pack(pady=8)

        self.chf = tk.Frame(r, bg=BG)
        sb = tk.Scrollbar(self.chf); sb.pack(side="right", fill="y")
        self.text = tk.Text(self.chf, bg=BG, fg=TXT,font=("Consolas",11),state="disabled", wrap="word", yscrollcommand=sb.set, relief="flat")
        self.text.pack(fill="both", expand=True)
        sb.config(command=self.text.yview)

        self.msgf = tk.Frame(r, bg=BG)
        self.msg_in = tk.Entry(self.msgf,bg=INP, fg=TXT, font=("Consolas",12), insertbackground=TXT, relief="flat")
        self.msg_in.pack(side="left", fill="x", expand=True, padx=5)
        self.msg_in.bind("<Return>", self.send_msg)
        tk.Button(self.msgf,text="SEND",bg=BTN,fg=TXT,font=("Consolas",10,"bold"),command=self.send_msg,relief="flat").pack(side="right", padx=5)

        self.user_in.focus_set()

    def join_chat(self, e=None):
        name = self.user_in.get().strip()
        if not name or len(name)>20 or any(ch in name for ch in "/\\:*?\"<>|"):
            return self._err("Invalid username")

        self.username = name
        self.connected = True
        self.logf.pack_forget()
        self.chf.pack(fill="both", expand=True, padx=10, pady=5)
        self.msgf.pack(fill="x", padx=10, pady=10)
        self.root.title(f"{name} - LAN Chat")

        m = {"type":"join","username":name,"ip":self.my_ip,"mac":self.my_mac,"id":self.my_id,"msg_id":str(uuid.uuid4())}
        self._send(m)
        self._add("Welcome!", BRG)

    def _send(self, d):
        try:
            enc = encrypt_message(json.dumps(d), KEY)
            main_sock.sendto(enc.encode(), (self.bc, PORT))
        except:
            self._add("Network issue", ERR)

    def _listen(self):
        global is_running
        while is_running:
            try:
                data, addr = main_sock.recvfrom(BUF)
            except socket.timeout:
                continue
            except:
                if self.connected: self._add("Network error", ERR)
                continue

            if not self.connected: continue
            try:
                dec = decrypt_message(data.decode(), KEY)
                obj = json.loads(dec)
            except:
                continue

            if obj.get("id")==self.my_id: continue
            mid = obj.get("msg_id")
            if mid and mid in self.hist: continue
            if mid:
                self.hist.add(mid)
                if len(self.hist)>500:
                    self.hist = set(list(self.hist)[-250:])

            t = obj.get("type")
            if t=="join":
                u = obj.get("username","?")
                self._add(f"{u} joined", BRG)
                self._sound("join")
                self._notify()
            elif t=="leave":
                u = obj.get("username","?")
                self._add(f"{u} left", ERR)
                self._sound("leave")
            elif t=="chat":
                u = obj.get("username","?")
                msg = obj.get("text","")
                self._add(f"{u}: {msg}", TXT)
                self._sound("msg")
                self._notify()
                self._blink()

    def _add(self, msg, col):
        def go():
            self.text.config(state="normal")
            t = datetime.now().strftime("%H:%M:%S")
            s = f"[{t}] {msg}\n"
            self.text.insert("end", s)
            self.text.tag_add("c","end-2l","end-1l")
            self.text.tag_config("c",foreground=col)
            self.text.config(state="disabled")
            self.text.see("end")
        self.root.after(0, go)

    def send_msg(self, e=None):
        m = self.msg_in.get().strip()
        if not m: return
        if len(m)>500: return self._err("Too long")
        if m.startswith("/"):
            return self._cmd(m)
        mid = str(uuid.uuid4())
        d = {"type":"chat","username":self.username,"text":m,"ip":self.my_ip,"mac":self.my_mac,"id":self.my_id,"msg_id":mid}
        self.hist.add(mid)
        self._send(d)
        self._add(f"You: {m}", TXT2)
        self.msg_in.delete(0, "end")

    def _cmd(self, c):
        c = c.strip().lower()
        if c=="/clear":
            self.text.config(state="normal"); self.text.delete(1.0,"end"); self.text.config(state="disabled")
            self._add("Cleared", BRG)
        elif c=="/help":
            self._add("Commands:\n/clear\n/help", BRG)
        else:
            self._add("Unknown cmd", ERR)

    def _sound(self, t):
        if not self.sounds: return
        try:
            if t in ("join","leave"): winsound.Beep(800,200)
            elif t=="msg": winsound.Beep(600,150)
            else: winsound.Beep(400,300)
        except:
            pass

    def _notify(self):
        if not self.notifs: return
        try:
            if not self.root.focus_get():
                self.root.attributes("-topmost",True)
                self.root.after(100,lambda: self.root.attributes("-topmost",False))
        except:
            pass

    def _blink(self):
        if not self.notifs: return
        old = self.root.title()
        self.root.title("** NEW MESSAGE ** " + old)
        self.root.after(2000, lambda: self.root.title(old))

    def _err(self, m):
        self._sound("err")
        try: messagebox.showerror("Error",m)
        except: pass

    def cleanup_and_exit(self):
        global is_running
        is_running=False
        if self.connected:
            try:
                self._send({"type":"leave","username":self.username,"ip":self.my_ip,"mac":self.my_mac,"id":self.my_id,"msg_id":str(uuid.uuid4())})
            except: pass
        try: main_sock.close()
        except: pass
        try: self.root.destroy()
        except: pass

if __name__=="__main__":
    print("Starting LAN Chat…")
    root = tk.Tk()
    app = LanChatApp(root)
    root.protocol("WM_DELETE_WINDOW", app.cleanup_and_exit)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        app.cleanup_and_exit()
