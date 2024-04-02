import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk
from scapy.all import ARP, Ether, srp
import threading


def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=3, verbose=False)[0]
    
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def print_devices(devices):
    device_info = ""
    device_info += "IP Address\t\tMAC Address\n"
    device_info += "-----------------------------------------\n"
    for device in devices:
        device_info += f"{device['ip']}\t\t{device['mac']}\n"
    return device_info

def scan_button_clicked():
    ip_network = entry_ip_network.get()
    network_bits = entry_network_bits.get()
    if ip_network and network_bits:
        ip_range = f"{ip_network}/{network_bits}"
        try:
            progress_bar.grid()
            progress_bar.start()
            devices = scan_network(ip_range)
            device_info = print_devices(devices)
            text_scan_result.delete("1.0", tk.END)
            text_scan_result.insert(tk.END, device_info)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
        finally:
            progress_bar.stop()
            progress_bar.grid_remove()
    else:
        messagebox.showwarning("Warning", "Please enter both IP network and network bits.")

def scan_in_background():
    threading.Thread(target=scan_button_clicked).start()

# GUI Setup
root = tk.Tk()
root.title("Network Recon Tool")

# Custom Style
style = ttk.Style()
style.configure("TButton", foreground="blue", background="lightgray", font=("Arial", 10))
style.configure("TLabel", foreground="black", background="lightgray", font=("Arial", 10))
style.configure("TEntry", foreground="black", background="white", font=("Arial", 10))
style.configure("TText", foreground="black", background="white", font=("Arial", 10))

label_ip_network = ttk.Label(root, text="IP Network:")
label_ip_network.grid(row=0, column=0, padx=10, pady=10, sticky="W")

entry_ip_network = ttk.Entry(root)
entry_ip_network.grid(row=0, column=1, padx=10, pady=10)

label_network_bits = ttk.Label(root, text="Network Bits:")
label_network_bits.grid(row=1, column=0, padx=10, pady=10, sticky="W")

entry_network_bits = ttk.Entry(root)
entry_network_bits.grid(row=1, column=1, padx=10, pady=10)

scan_button = ttk.Button(root, text="Scan", command=scan_in_background)
scan_button.grid(row=1, column=2, padx=10, pady=10)

progress_bar = ttk.Progressbar(root, orient='horizontal', mode='indeterminate')
progress_bar.grid(row=2, column=0, columnspan=3, pady=10)
progress_bar.grid_remove()  

text_scan_result = scrolledtext.ScrolledText(root, width=50, height=20)
text_scan_result.grid(row=3, column=0, columnspan=3, padx=10, pady=10)

root.mainloop()
