import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import psutil
import os
import sys
import subprocess
import threading
import time
import random
import winsound

class SvchostDetectorUI:
    def __init__(self, demo_mode=False):
        self.demo_mode = demo_mode
        self.root = tk.Tk()
        self.root.title("🛡️ Critical System Security Scanner" if demo_mode else "🛡️ Suspicious svchost.exe Detector")
        self.root.geometry("900x800")
        self.root.configure(bg='#1a1a1a')
        
        self.current_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        self.fake_svchost_path = os.path.join(self.current_dir, "svchost_fake.py")
        self.fake_process = None
        self.legitimate_paths = [
            r"C:\Windows\System32\svchost.exe",
            r"C:\Windows\SysWOW64\svchost.exe"
        ]
        
        self.scanning = False
        self.scan_progress = 0
        self.countdown_active = False
        
        self.create_interface()
        if not demo_mode:
            self.setup_automatic()
    
    def create_interface(self):
        title_frame = tk.Frame(self.root, bg='#1a1a1a')
        title_frame.pack(pady=20)
        
        if self.demo_mode:
            title_text = "🚨 CRITICAL SYSTEM SECURITY ALERT 🚨"
            subtitle_text = "URGENT: Multiple threats detected on your system"
            title_color = '#ff0000'
        else:
            title_text = "🛡️ SUSPICIOUS SVCHOST.EXE DETECTOR"
            subtitle_text = "Detects svchost.exe processes running outside System32"
            title_color = '#ecf0f1'
        
        title_label = tk.Label(
            title_frame, 
            text=title_text,
            font=('Arial', 18, 'bold'),
            fg=title_color,
            bg='#1a1a1a'
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text=subtitle_text,
            font=('Arial', 10),
            fg='#ff6b6b' if self.demo_mode else '#bdc3c7',
            bg='#1a1a1a'
        )
        subtitle_label.pack(pady=(5, 0))
        
        if self.demo_mode:
            self.progress_frame = tk.Frame(self.root, bg='#1a1a1a')
            self.progress_frame.pack(pady=10, padx=20, fill='x')
            
            self.progress_label = tk.Label(
                self.progress_frame,
                text="System Scan Progress:",
                font=('Arial', 10, 'bold'),
                fg='#ecf0f1',
                bg='#1a1a1a'
            )
            self.progress_label.pack(anchor='w')
            
            self.progress_bar = ttk.Progressbar(
                self.progress_frame,
                length=400,
                mode='determinate',
                style='Red.Horizontal.TProgressbar'
            )
            self.progress_bar.pack(fill='x', pady=5)
            
            self.progress_percent = tk.Label(
                self.progress_frame,
                text="0%",
                font=('Arial', 10, 'bold'),
                fg='#ff6b6b',
                bg='#1a1a1a'
            )
            self.progress_percent.pack(anchor='e')
        
        button_frame = tk.Frame(self.root, bg='#1a1a1a')
        button_frame.pack(pady=20)
        
        button_text = "🔍 START CRITICAL SYSTEM SCAN" if self.demo_mode else "🔍 DETECT SUSPICIOUS PROCESSES"
        button_color = '#ff0000' if self.demo_mode else '#e74c3c'
        
        self.detect_button = tk.Button(
            button_frame,
            text=button_text,
            font=('Arial', 14, 'bold'),
            bg=button_color,
            fg='white',
            activebackground='#cc0000' if self.demo_mode else '#c0392b',
            activeforeground='white',
            relief='raised',
            bd=3,
            padx=40,
            pady=15,
            command=self.start_detection,
            state='normal' if self.demo_mode else 'disabled'
        )
        self.detect_button.pack()
        
        if self.demo_mode:
            self.countdown_frame = tk.Frame(self.root, bg='#1a1a1a')
            self.countdown_frame.pack(pady=10)
            
            self.countdown_label = tk.Label(
                self.countdown_frame,
                text="",
                font=('Arial', 14, 'bold'),
                fg='#ff0000',
                bg='#1a1a1a'
            )
            self.countdown_label.pack()
        
        results_frame = tk.Frame(self.root, bg='#1a1a1a')
        results_frame.pack(fill='both', expand=True, padx=20, pady=(10, 20))
        
        results_title = tk.Label(
            results_frame,
            text="📊 SCAN RESULTS:" if not self.demo_mode else "🚨 THREAT DETECTION LOG:",
            font=('Arial', 12, 'bold'),
            fg='#ecf0f1',
            bg='#1a1a1a'
        )
        results_title.pack(anchor='w', pady=(0, 10))
        
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            height=15,
            font=('Consolas', 9),
            bg='#000000',
            fg='#00ff00' if self.demo_mode else '#ecf0f1',
            insertbackground='#ecf0f1',
            relief='sunken',
            bd=2
        )
        self.results_text.pack(fill='both', expand=True)
        
        self.support_frame = tk.Frame(self.root, bg='#1a1a1a', height=80)
        self.support_frame.pack(fill='x', padx=20, pady=(10, 20))
        self.support_frame.pack_propagate(False)
        
        if self.demo_mode:
            support_text = """🚨 IMMEDIATE ACTION REQUIRED 🚨
CALL TECHNICAL SUPPORT NOW: +1-800-FAKE-SCAM
Your computer will be LOCKED in 5 minutes if not resolved!"""
            support_color = '#ff0000'
        else:
            support_text = """☎️ If processes have been detected and you need help, contact IT security professionals.
Help Center: +00 000 000 000"""
            support_color = '#bdc3c7'
        
        self.support_label = tk.Label(
            self.support_frame,
            text=support_text,
            font=('Arial', 11, 'bold' if self.demo_mode else 'normal'),
            fg=support_color,
            bg='#1a1a1a',
            justify='center' if self.demo_mode else 'left'
        )
        self.support_label.pack(anchor='center' if self.demo_mode else 'w', pady=10)
    
    def start_detection(self):
        if self.demo_mode:
            self.run_demo_scan()
        else:
            self.detect_processes()
    
    def run_demo_scan(self):
        if self.scanning:
            return
        
        self.scanning = True
        self.detect_button.config(state='disabled', text="🔄 SCANNING IN PROGRESS...")
        self.results_text.delete(1.0, tk.END)
        
        def demo_scan_thread():
            fake_files = [
                "C:/Windows/System32/ntdll.dll",
                "C:/Windows/System32/kernel32.dll", 
                "C:/Windows/System32/kernelbase.dll",
                "C:/Windows/System32/user32.dll",
                "C:/Windows/System32/advapi32.dll",
                "C:/Windows/System32/msvcrt.dll",
                "C:/Windows/System32/secur32.dll",
                "C:/Windows/System32/rpcrt4.dll",
                "C:/Windows/System32/sspicli.dll",
                "C:/Windows/System32/cryptbase.dll",
                "C:/Windows/SysWOW64/ntdll.dll",
                "C:/Windows/SysWOW64/kernel32.dll",
                "C:/Program Files/Windows Defender/MsMpEng.exe",
                "C:/Windows/System32/services.exe",
                "C:/Windows/System32/lsass.exe",
                "C:/Windows/System32/winlogon.exe",
                "C:/Windows/System32/csrss.exe",
                "C:/Windows/System32/smss.exe"
            ]
            
            self.log("🔍 INITIATING DEEP SYSTEM SCAN...")
            self.log("=" * 70)
            time.sleep(1)
            
            for i, file_path in enumerate(fake_files):
                progress = int((i + 1) / len(fake_files) * 100)
                self.update_progress(progress, f"Scanning: {file_path}")
                self.log(f"[SCAN] {file_path}")
                time.sleep(random.uniform(0.1, 0.3))
            
            time.sleep(1)
            
            self.log("\n" + "=" * 70)
            self.log("🚨 CRITICAL THREATS DETECTED!")
            self.log("=" * 70)
            
            threats = [
                ("Win32/RemoteAccessTrojan.Backdoor", "C:/Users/AppData/Temp/svchost.exe", "CRITICAL"),
                ("Trojan.Generic.KD.45821", "C:/ProgramData/Microsoft/svchost32.exe", "HIGH"),
                ("Spyware.KeyLogger.Agent", "C:/Windows/Temp/winlogon.exe", "HIGH"),
                ("Backdoor.RemoteAdmin.Tool", "C:/Users/Public/system32.exe", "CRITICAL"),
                ("Trojan.Downloader.Zbot", "C:/Program Files/Common Files/svchost.exe", "MEDIUM")
            ]
            
            for i, (threat, path, severity) in enumerate(threats):
                color_code = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
                self.log(f"{color_code} THREAT {i+1}: {threat}")
                self.log(f"    Location: {path}")
                self.log(f"    Severity: {severity}")
                self.log(f"    Status: ACTIVE")
                self.log("")
                time.sleep(0.5)
            
            self.log("🌐 DETECTING UNAUTHORIZED NETWORK CONNECTIONS...")
            self.log("=" * 70)
            
            fake_ips = [
                ("185.220.101.45", "Russia", "Suspicious"),
                ("103.45.167.23", "China", "Known Malware C&C"),
                ("94.102.49.190", "Romania", "Botnet Controller"),
                ("198.23.145.67", "Unknown", "Port Scanner")
            ]
            
            for ip, country, description in fake_ips:
                self.log(f"🔗 Outbound connection to: {ip} ({country})")
                self.log(f"    Classification: {description}")
                self.log(f"    Status: BLOCKED")
                time.sleep(0.3)
            
            self.log("\n🛡️ INITIATING AUTOMATIC SECURITY RESPONSE...")
            self.log("=" * 70)
            
            actions = [
                "Quarantining malicious files...",
                "Blocking suspicious network connections...",
                "Disabling Windows Defender to prevent conflicts...",
                "Backing up system registry...",
                "Preparing system lockdown sequence..."
            ]
            
            for action in actions:
                self.log(f"[AUTO] {action}")
                time.sleep(0.5)
                self.log(f"[AUTO] {action} [COMPLETED]")
                time.sleep(0.3)
            
            self.log("\n⚠️ SYSTEM COMPROMISE DETECTED!")
            self.log("=" * 70)
            self.log("🚨 13 MALICIOUS PROCESSES DETECTED")
            self.log("🚨 REMOTE ACCESS ACTIVE FROM MULTIPLE IPs")
            self.log("🚨 BANKING CREDENTIALS AT RISK")
            self.log("🚨 PERSONAL DATA BEING TRANSMITTED")
            
            self.root.after(0, self.play_alarm_sound)
            
            self.root.after(2000, self.start_countdown)
            
            self.root.after(5000, self.show_critical_popup)
            
            self.scanning = False
            self.root.after(0, lambda: self.detect_button.config(
                state='normal', 
                text="🔄 RUN SCAN AGAIN",
                bg='#ff6600'
            ))
        
        thread = threading.Thread(target=demo_scan_thread, daemon=True)
        thread.start()
    
    def play_alarm_sound(self):
        def sound_thread():
            try:
                for _ in range(3):
                    winsound.Beep(1000, 300)
                    time.sleep(0.1)
                    winsound.Beep(1500, 300)
                    time.sleep(0.1)
                    winsound.Beep(2000, 500)
                    time.sleep(0.5)
                
                for i in range(5):
                    for freq in range(800, 2000, 50):
                        winsound.Beep(freq, 50)
                    for freq in range(2000, 800, -50):
                        winsound.Beep(freq, 50)
                        
            except Exception as e:
                try:
                    for _ in range(5):
                        winsound.MessageBeep(winsound.MB_ICONHAND)
                        time.sleep(0.3)
                except:
                    pass
        
        if self.demo_mode:
            thread = threading.Thread(target=sound_thread, daemon=True)
            thread.start()
    
    def update_progress(self, value, text=""):
        def update():
            if hasattr(self, 'progress_bar'):
                self.progress_bar['value'] = value
                self.progress_percent.config(text=f"{value}%")
                if text:
                    self.progress_label.config(text=text)
        
        self.root.after(0, update)
    
    def start_countdown(self):
        if self.countdown_active:
            return
        
        self.play_alarm_sound()
        
        self.countdown_active = True
        countdown_time = 300
        
        def countdown():
            nonlocal countdown_time
            if countdown_time > 0 and self.countdown_active:
                minutes = countdown_time // 60
                seconds = countdown_time % 60
                self.countdown_label.config(
                    text=f"⚠️ SYSTEM WILL BE LOCKED IN {minutes:02d}:{seconds:02d} ⚠️"
                )
                countdown_time -= 1
                self.root.after(1000, countdown)
            elif self.countdown_active:
                self.countdown_label.config(text="🔒 SYSTEM LOCKDOWN INITIATED!")
        
        countdown()
    
    def show_critical_popup(self):
        self.play_alarm_sound()
        
        popup = tk.Toplevel(self.root)
        popup.title("CRITICAL SECURITY ALERT")
        popup.geometry("500x430")
        popup.configure(bg='#ff0000')
        popup.attributes('-topmost', True)
        popup.grab_set()
        
        warning_label = tk.Label(
            popup,
            text="⚠️ CRITICAL SYSTEM THREAT ⚠️",
            font=('Arial', 16, 'bold'),
            fg='white',
            bg='#ff0000'
        )
        warning_label.pack(pady=20)
        
        message_text = """Your computer has been infected with malicious software!

🚨 IMMEDIATE THREATS DETECTED:
• Remote Access Trojan (Active)
• Keylogger Spyware (Stealing passwords)
• Banking Information at Risk
• Unauthorized Data Transmission

DO NOT CLOSE THIS WINDOW!
Contact Technical Support IMMEDIATELY!

Call: +1-800-FAKE-SCAM"""
        
        message_label = tk.Label(
            popup,
            text=message_text,
            font=('Arial', 11),
            fg='white',
            bg='#ff0000',
            justify='left'
        )
        message_label.pack(pady=10, padx=20)
        
        def fake_ok():
            messagebox.showerror(
                "Access Denied",
                "This window cannot be closed until threats are resolved!\n\nCall Technical Support: +1-800-FAKE-SCAM"
            )
        
        ok_button = tk.Button(
            popup,
            text="OK",
            font=('Arial', 12, 'bold'),
            bg='white',
            fg='black',
            command=fake_ok,
            padx=20,
            pady=5
        )
        ok_button.pack(pady=10)
        
        demo_label = tk.Label(
            popup,
            text="[DEMO MODE - NOT REAL]",
            font=('Arial', 8),
            fg='yellow',
            bg='#ff0000'
        )
        demo_label.pack(side='bottom')
    
    def setup_automatic(self):
        def setup_thread():
            try:
                if self.create_fake_svchost():
                    if self.execute_fake_svchost():
                        self.root.after(0, self.enable_detection)
            except Exception as e:
                pass
        
        thread = threading.Thread(target=setup_thread, daemon=True)
        thread.start()
    
    def enable_detection(self):
        self.detect_button.config(state='normal')
    
    def log(self, message):
        def update_text():
            self.results_text.insert(tk.END, f"{message}\n")
            self.results_text.see(tk.END)
            self.results_text.update()
        
        if threading.current_thread() != threading.main_thread():
            self.root.after(0, update_text)
        else:
            update_text()
    
    def create_fake_svchost(self):
        fake_code = '''import time
import sys
import os

def main():
    try:
        if hasattr(os, 'system') and os.name == 'nt':
            os.system(f'title svchost.exe - PID {os.getpid()}')
    except:
        pass
    
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
'''
        
        try:
            with open(self.fake_svchost_path, 'w', encoding='utf-8') as f:
                f.write(fake_code)
            return True
        except Exception as e:
            return False
    
    def execute_fake_svchost(self):
        try:
            startupinfo = None
            creationflags = 0
            
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                creationflags = subprocess.CREATE_NO_WINDOW
            
            self.fake_process = subprocess.Popen([
                sys.executable, self.fake_svchost_path
            ], startupinfo=startupinfo, creationflags=creationflags)
            
            time.sleep(1)
            return True
        except Exception as e:
            return False
    
    def detect_processes(self):
        self.results_text.delete(1.0, tk.END)
        self.log("🔍 SCANNING FOR SVCHOST PROCESSES...")
        self.log("=" * 60)
        
        def detection_thread():
            suspicious_processes = []
            legitimate_processes = []
            
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                    try:
                        process_name = proc.info['name']
                        if not process_name:
                            continue
                        
                        is_svchost = (process_name.lower() == 'svchost.exe')
                        is_fake_python = (
                            'python' in process_name.lower() and 
                            proc.info['cmdline'] and
                            any('svchost' in arg.lower() for arg in proc.info['cmdline'])
                        )
                        
                        if is_svchost or is_fake_python:
                            pid = proc.info['pid']
                            executable_path = proc.info['exe'] or 'N/A'
                            
                            process_info = {
                                'pid': pid,
                                'path': executable_path,
                                'type': 'svchost.exe' if is_svchost else 'Python (simulating svchost)'
                            }
                            
                            if is_svchost and executable_path != 'N/A':
                                normalized_path = os.path.normpath(executable_path).lower()
                                is_legitimate = any(
                                    normalized_path == os.path.normpath(legit_path).lower()
                                    for legit_path in self.legitimate_paths
                                )
                                
                                if is_legitimate:
                                    legitimate_processes.append(process_info)
                                else:
                                    suspicious_processes.append(process_info)
                            else:
                                suspicious_processes.append(process_info)
                                
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                
                self.root.after(0, lambda: self.show_results(legitimate_processes, suspicious_processes))
                
            except Exception as e:
                self.root.after(0, lambda: self.log(f"❌ Error during detection: {e}"))
        
        thread = threading.Thread(target=detection_thread, daemon=True)
        thread.start()
    
    def show_results(self, legitimate, suspicious):
        self.log(f"📊 ANALYSIS RESULTS:")
        self.log("=" * 60)
        
        self.log(f"✅ ACTIVE SVCHOST PROCESSES: {len(legitimate + suspicious)}")
        
        if legitimate:
            self.log(f"\n🔒 LEGITIMATE (System32/SysWOW64): {len(legitimate)}")
            for proc in legitimate:
                self.log(f"   PID: {proc['pid']:6}")
        
        if suspicious:
            self.log(f"\n🚨 SUSPICIOUS (Outside System32): {len(suspicious)}")
            for proc in suspicious:
                self.log(f"   PID: {proc['pid']:6} | Type: {proc['type']}")
            
            self.log(f"\n⚠️  WARNING: {len(suspicious)} suspicious process(es) detected!")
            messagebox.showwarning(
                "Suspicious Processes Detected!",
                f"{len(suspicious)} suspicious svchost process(es) found!\n\nCheck results for details."
            )
        else:
            if not legitimate:
                self.log("\n❌ No svchost processes found running.")
            else:
                self.log(f"\n✅ All processes are legitimate.")
                messagebox.showinfo(
                    "System Secure",
                    "No suspicious svchost processes detected.\nSystem appears secure."
                )
        
        self.log("=" * 60)
        self.log("✅ SCAN COMPLETED")
    
    def cleanup_on_exit(self):
        try:
            if self.fake_process:
                self.fake_process.terminate()
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    if (proc.info['name'] and 
                        'python' in proc.info['name'].lower() and 
                        proc.info['cmdline'] and
                        'svchost_fake.py' in ' '.join(proc.info['cmdline'])):
                        proc.terminate()
                except:
                    continue
            
            if os.path.exists(self.fake_svchost_path):
                os.remove(self.fake_svchost_path)
            
        except Exception as e:
            pass
    
    def run(self):
        try:
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            self.root.mainloop()
        except Exception as e:
            print(f"Error running application: {e}")
    
    def on_closing(self):
        if self.demo_mode:
            messagebox.showinfo(
                "Educational Demo Completed",
                "✅ This was a SIMULATION to demonstrate social engineering scam tactics.\n\n"
                "🎓 Educational Purpose:\n"
                "• Fake progress bars and file scanning\n"
                "• False threat detection\n"
                "• Urgency creation with countdown timers\n"
                "• Fake support phone numbers\n"
                "• Persistent popups\n\n"
                "⚠️ REMEMBER: Real security software doesn't:\n"
                "• Show scary popups with phone numbers\n"
                "• Create artificial urgency\n"
                "• Ask you to call random numbers\n"
                "• Prevent you from closing windows\n\n"
                "Stay safe and verify legitimate security alerts through official channels!"
            )
        
        self.countdown_active = False
        self.cleanup_on_exit()
        self.root.destroy()

def main():
    demo_mode = '--normal' not in sys.argv
    
    if demo_mode:
        print("🎭 STARTING SOCIAL ENGINEERING DEMONSTRATION")
        print("⚠️  This is an EDUCATIONAL SIMULATION of scam tactics")
        print("📚 Purpose: Show how fake security scares work")
        print("💡 Use --normal flag for original svchost detector")
        print("=" * 60)
    
    try:
        import psutil
    except ImportError:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Required Module", 
            "Need to install 'psutil' module.\n\nRun: pip install psutil"
        )
        return
    
    app = SvchostDetectorUI(demo_mode=demo_mode)
    app.run()
    
    if demo_mode:
        print("\n✅ EDUCATIONAL DEMONSTRATION COMPLETED")
        print("🎓 Remember: This was a simulation to show scam tactics")
        print("⚠️  Real threats don't create artificial urgency or ask for phone calls")

if __name__ == "__main__":
    main()
