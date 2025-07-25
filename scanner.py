import socket
from concurrent.futures import ThreadPoolExecutor
import time
import csv
import tkinter as tk
from tkinter import messagebox, filedialog

def scan_port(ip, port, results):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((ip, port))
        try:
            banner = sock.recv(1024).decode().strip()
        except:
            banner = ''
        service = detect_service(port, banner)
        result = {"Port": port, "Service": service, "Banner": banner}
        results.append(result)
        sock.close()
    except:
        pass

def detect_service(port, banner):
    # Simple heuristic: based on common ports or banner content
    common_services = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                       80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL"}
    if port in common_services:
        return common_services[port]
    elif "ssh" in banner.lower():
        return "SSH"
    elif "http" in banner.lower():
        return "HTTP"
    else:
        return "Unknown"

def start_scan(target, start_port, end_port, output_text):
    ports = range(start_port, end_port+1)
    results = []
    start_time = time.time()
    output_text.insert(tk.END, f"Scanning {target} ports {start_port}-{end_port}...\n\n")
    output_text.update()

    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in ports:
            executor.submit(scan_port, target, port, results)

    elapsed = time.time() - start_time

    if results:
        output_text.insert(tk.END, f"\nFound {len(results)} open ports:\n")
        for res in results:
            output_text.insert(tk.END, f"Port {res['Port']} open | Service: {res['Service']} | Banner: {res['Banner']}\n")
    else:
        output_text.insert(tk.END, "\nNo open ports found.\n")

    output_text.insert(tk.END, f"\nScan complete in {elapsed:.2f} seconds.\n")
    output_text.update()

    # Ask user to save CSV
    save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
    if save_path:
        with open(save_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["Port", "Service", "Banner"])
            writer.writeheader()
            writer.writerows(results)
        messagebox.showinfo("Success", f"Results saved to {save_path}")

def gui_app():
    root = tk.Tk()
    root.title("Advanced Port Scanner")
    root.geometry("700x500")

    tk.Label(root, text="Target IP:").pack()
    ip_entry = tk.Entry(root, width=40)
    ip_entry.pack()

    tk.Label(root, text="Start Port:").pack()
    start_port_entry = tk.Entry(root, width=20)
    start_port_entry.pack()

    tk.Label(root, text="End Port:").pack()
    end_port_entry = tk.Entry(root, width=20)
    end_port_entry.pack()

    output_text = tk.Text(root, height=20)
    output_text.pack()

    def on_scan():
        target = ip_entry.get()
        try:
            start_port = int(start_port_entry.get())
            end_port = int(end_port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter valid port numbers.")
            return
        if not target:
            messagebox.showerror("Error", "Please enter target IP.")
            return
        output_text.delete(1.0, tk.END)
        start_scan(target, start_port, end_port, output_text)

    scan_button = tk.Button(root, text="Start Scan", command=on_scan)
    scan_button.pack()

    root.mainloop()

if __name__ == "__main__":
    gui_app()


