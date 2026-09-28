import tkinter as tk
from tkinter import ttk, messagebox
import threading

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

def run_scan(target, scan_type):
    text_log.config(state=tk.NORMAL)
    text_log.insert(tk.END, f"[*] Initializing Nmap Scan Engine...\n")
    
    if not NMAP_AVAILABLE:
        text_log.insert(tk.END, "[!] FATAL: 'python-nmap' module not found.\n")
        text_log.config(state=tk.DISABLED)
        btn_scan.config(state=tk.NORMAL)
        lbl_status.config(text="Dependency Missing", fg="#c0392b")
        return

    try:
        nm = nmap.PortScanner()
        
        # Map friendly GUI names to actual Nmap CLI flags
        flags = "-sn" # Default
        if scan_type == "Ping Sweep (-sn)":
            flags = "-sn"
        elif scan_type == "Quick Port Scan (-F)":
            flags = "-F -T4"
        elif scan_type == "Aggressive Scan (-A)":
            flags = "-A -T4"
        elif scan_type == "OS Detection (-O)":
            flags = "-O -T4"

        text_log.insert(tk.END, f"[*] Target: {target}\n")
        text_log.insert(tk.END, f"[*] Executing Flags: nmap {flags} {target}\n")
        text_log.insert(tk.END, "-" * 55 + "\n")
        text_log.see(tk.END)
        
        # Execute the scan (this blocks the thread, which is why we run it in the background)
        nm.scan(hosts=target, arguments=flags)
        
        if not nm.all_hosts():
            text_log.insert(tk.END, f"[!] No hosts found or host is blocking ping probes.\n")
        else:
            for host in nm.all_hosts():
                # Display Hostname and Status
                hostname = nm[host].hostname() if nm[host].hostname() else "Unknown"
                text_log.insert(tk.END, f"Host: {host} ({hostname})\n")
                text_log.insert(tk.END, f"State: {nm[host].state().upper()}\n")
                
                # Iterate through discovered protocols (TCP/UDP)
                for proto in nm[host].all_protocols():
                    text_log.insert(tk.END, f"Protocol: {proto.upper()}\n")
                    ports = nm[host][proto].keys()
                    
                    for port in sorted(ports):
                        state = nm[host][proto][port]['state']
                        name = nm[host][proto][port]['name']
                        text_log.insert(tk.END, f"  -> Port {port:5}: {state:8} [{name}]\n")
                
                text_log.insert(tk.END, "-" * 55 + "\n")

        text_log.insert(tk.END, f"[*] Scan Complete.\n\n")
        lbl_status.config(text="Scan Complete", fg="#27ae60")
        
    except nmap.PortScannerError as e:
        text_log.insert(tk.END, f"[!] Nmap Execution Error: {str(e)}\n")
        text_log.insert(tk.END, "Hint: Does Nmap exist in your system PATH?\n")
        lbl_status.config(text="Execution Failed", fg="#c0392b")
    except Exception as e:
        text_log.insert(tk.END, f"[!] Unexpected Error: {str(e)}\n")
        lbl_status.config(text="Error", fg="#c0392b")
        
    text_log.see(tk.END)
    text_log.config(state=tk.DISABLED)
    btn_scan.config(state=tk.NORMAL)

def start_scan():
    target = entry_target.get().strip()
    scan_type = combo_scan.get()
    
    if not target:
        messagebox.showerror("Input Error", "Please enter a target IP, CIDR, or domain.")
        return

    btn_scan.config(state=tk.DISABLED)
    lbl_status.config(text="Scanning target in background...", fg="#e67e22")
    
    text_log.config(state=tk.NORMAL)
    text_log.delete(1.0, tk.END)
    text_log.config(state=tk.DISABLED)
    
    # Offload Nmap execution to a background thread
    threading.Thread(target=run_scan, args=(target, scan_type), daemon=True).start()

# --- Tkinter GUI Layout ---
root = tk.Tk()
root.title("SOC Toolkit - Nmap Security Scanner")
root.geometry("600x520")
root.resizable(False, False)

frame = ttk.Frame(root, padding="15")
frame.pack(fill=tk.BOTH, expand=True)

lbl_title = tk.Label(frame, text="Nmap GUI Automation Wrapper", font=("Helvetica", 13, "bold"))
lbl_title.pack(anchor="w", pady=(0, 15))

# Target Configuration
config_frame = tk.Frame(frame)
config_frame.pack(fill=tk.X, pady=(0, 15))

tk.Label(config_frame, text="Target (IP/Domain):", font=("Helvetica", 9)).grid(row=0, column=0, sticky="w", pady=5)
entry_target = ttk.Entry(config_frame, width=25)
entry_target.grid(row=0, column=1, padx=10, pady=5)
entry_target.insert(0, "127.0.0.1")

tk.Label(config_frame, text="Scan Profile:", font=("Helvetica", 9)).grid(row=1, column=0, sticky="w", pady=5)
combo_scan = ttk.Combobox(config_frame, values=["Ping Sweep (-sn)", "Quick Port Scan (-F)", "Aggressive Scan (-A)", "OS Detection (-O)"], state="readonly", width=22)
combo_scan.grid(row=1, column=1, padx=10, pady=5)
combo_scan.current(1)

# Controls
control_frame = tk.Frame(frame)
control_frame.pack(fill=tk.X, pady=(0, 10))

btn_scan = tk.Button(control_frame, text="Launch Nmap Scan", command=start_scan, bg="#2980b9", fg="white", font=("Helvetica", 9, "bold"), width=20)
btn_scan.pack(side=tk.LEFT)

lbl_status = tk.Label(control_frame, text="Ready", font=("Helvetica", 9, "bold"), fg="#7f8c8d")
lbl_status.pack(side=tk.RIGHT, padx=(0, 5))

# Output Console
text_frame = tk.Frame(frame)
text_frame.pack(fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(text_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

text_log = tk.Text(text_frame, font=("Consolas", 9), bg="#1e1e1e", fg="#ecf0f1", yscrollcommand=scrollbar.set)
text_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
text_log.config(state=tk.DISABLED)

scrollbar.config(command=text_log.yview)

root.mainloop()