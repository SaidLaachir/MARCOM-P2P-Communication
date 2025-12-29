import customtkinter as ctk
import threading
import socket
import sys
import re
import os

import server
import client

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# ==================================================
# CONSOLE REDIRECT (SUPPRESSION ANSI + COULEURS)
# ==================================================
class ConsoleRedirect:
    ANSI_ESCAPE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

    def __init__(self, widget):
        self.widget = widget
        self._init_tags()

    def _init_tags(self):
        self.widget.tag_config("NETWORK", foreground="#4FC3F7")
        self.widget.tag_config("KEY", foreground="#FFD54F")
        self.widget.tag_config("ELGAMAL", foreground="#BA68C8")
        self.widget.tag_config("AES", foreground="#81C784")
        self.widget.tag_config("SHA", foreground="#FFB74D")
        self.widget.tag_config("DSS", foreground="#E57373")
        self.widget.tag_config("DEFAULT", foreground="white")

    def write(self, msg):
        clean_msg = self.ANSI_ESCAPE.sub('', msg)

        tag = "DEFAULT"
        if "SERVER" in clean_msg or "CLIENT" in clean_msg or "listening" in clean_msg:
            tag = "NETWORK"
        elif "KEY" in clean_msg:
            tag = "KEY"
        elif "ELGAMAL" in clean_msg:
            tag = "ELGAMAL"
        elif "AES" in clean_msg:
            tag = "AES"
        elif "SHA-256" in clean_msg:
            tag = "SHA"
        elif "DSS" in clean_msg:
            tag = "DSS"

        self.widget.configure(state="normal")
        self.widget.insert("end", clean_msg, tag)
        self.widget.see("end")
        self.widget.configure(state="disabled")

    def flush(self):
        pass


# ==================================================
# APPLICATION GUI
# ==================================================
class SecureChatGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        # ===== TITRE & ICÔNE =====
        self.title("MARCOM")

        try:
            base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
            icon_path = os.path.join(base_path, "icon.ico")
            self.iconbitmap(icon_path)
        except Exception:
            pass  # sécurité: ne casse jamais l'app

        self.geometry("1200x750")
        self.minsize(1100, 700)

        self.running = False
        self.connected = False

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ================= LEFT PANEL =================
        sidebar = ctk.CTkFrame(self, width=260, corner_radius=15)
        sidebar.grid(row=0, column=0, padx=15, pady=15, sticky="ns")

        ctk.CTkLabel(
            sidebar,
            text="Connection",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=20)

        self.role = ctk.StringVar(value="server")
        ctk.CTkRadioButton(sidebar, text="Server",
                           variable=self.role, value="server").pack(anchor="w", padx=20)
        ctk.CTkRadioButton(sidebar, text="Client",
                           variable=self.role, value="client").pack(anchor="w", padx=20)

        self.ip_entry = ctk.CTkEntry(sidebar)
        self.ip_entry.pack(padx=20, pady=12, fill="x")
        self.ip_entry.insert(0, self.get_local_ip())

        self.connect_btn = ctk.CTkButton(
            sidebar,
            text="Establish Connection",
            height=38,
            command=self.toggle
        )
        self.connect_btn.pack(padx=20, pady=10, fill="x")

        self.status = ctk.CTkLabel(
            sidebar,
            text="● Idle",
            text_color="gray",
            font=ctk.CTkFont(weight="bold")
        )
        self.status.pack(pady=20)

        # ================= MAIN PANEL =================
        main = ctk.CTkFrame(self, corner_radius=15)
        main.grid(row=0, column=1, padx=15, pady=15, sticky="nsew")
        main.grid_rowconfigure(1, weight=1)
        main.grid_columnconfigure(0, weight=1)

        self.console = ctk.CTkTextbox(main)
        self.console.grid(row=1, column=0, padx=15, pady=15, sticky="nsew")
        self.console.configure(state="disabled")

        # ================= CHAT INPUT =================
        input_frame = ctk.CTkFrame(main)
        input_frame.grid(row=2, column=0, padx=15, pady=10, sticky="ew")
        input_frame.grid_columnconfigure(0, weight=1)

        self.msg_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Type your message here…"
        )
        self.msg_entry.grid(row=0, column=0, padx=(0, 10), sticky="ew")
        self.msg_entry.bind("<Return>", self.send_message)

        self.send_btn = ctk.CTkButton(
            input_frame,
            text="Send",
            width=120,
            command=self.send_message
        )
        self.send_btn.grid(row=0, column=1)

        self.enable_chat(False)

        sys.stdout = ConsoleRedirect(self.console)
        sys.stderr = ConsoleRedirect(self.console)

        print("====== NETWORK ======")
        print("[GUI] MARCOM ready.\n")

    # ================= UTIL =================
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def enable_chat(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        self.msg_entry.configure(state=state)
        self.send_btn.configure(state=state)

    # ================= CONNECTION =================
    def toggle(self):
        if self.running:
            self.stop()
        else:
            self.start()

    def start(self):
        self.running = True
        self.connect_btn.configure(text="Stop Connection")

        if self.role.get() == "server":
            self.status.configure(text="● Listening", text_color="orange")
            threading.Thread(target=self.run_server, daemon=True).start()
        else:
            self.status.configure(text="● Connecting", text_color="orange")
            threading.Thread(target=self.run_client, daemon=True).start()

    def run_server(self):
        try:
            server.start_server(print)
            self.connected = True
            self.enable_chat(True)
            self.status.configure(text="● Connected", text_color="green")
            server.receive_messages(print)
        except Exception as e:
            print(f"[SERVER ERROR] {e}")
        finally:
            self.force_reset()

    def run_client(self):
        try:
            client.start_client(self.ip_entry.get(), print)
            self.connected = True
            self.enable_chat(True)
            self.status.configure(text="● Connected", text_color="green")
            client.receive_messages(print)
        except Exception as e:
            print(f"[CLIENT ERROR] {e}")
        finally:
            self.force_reset()

    def stop(self):
        try:
            if server.conn:
                server.conn.close()
                server.conn = None
            if client.sock:
                client.sock.close()
                client.sock = None
        except Exception:
            pass
        self.force_reset()

    def force_reset(self):
        if not self.running:
            return
        self.running = False
        self.connected = False
        self.enable_chat(False)
        self.connect_btn.configure(text="Establish Connection")
        self.status.configure(text="● Disconnected", text_color="red")
        print("[GUI] Connection closed.\n")

    # ================= CHAT =================
    def send_message(self, event=None):
        msg = self.msg_entry.get().strip()
        if not msg or not self.connected:
            return

        try:
            if self.role.get() == "server":
                server.send_message(msg, print)
            else:
                client.send_message(msg, print)
            self.msg_entry.delete(0, "end")
        except Exception as e:
            print(f"[SEND ERROR] {e}")


if __name__ == "__main__":
    app = SecureChatGUI()
    app.mainloop()
