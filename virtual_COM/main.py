import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from datetime import datetime
import socket
import threading
import struct

class CANFrameReceiverGUI:
    def __init__(self, master):
        self.master = master
        master.title("CAN Frame Receiver")

        self.receive_thread = None
        self.running = False
        self.received_data = {"Transceiver1": "", "Transceiver2": "", "ADC": ""}

        self.create_text_area()
        self.create_export_options()
        self.start_socket_server()

    def create_text_area(self):
        text_frame = tk.Frame(self.master)
        text_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Title for Data
        text_title_label = tk.Label(text_frame, text="Data", font=("Helvetica", 14, "bold"))
        text_title_label.pack()

        self.text_areas = {}
        for source in self.received_data:
            frame = tk.Frame(text_frame, width=200)
            frame.pack(expand=True, fill=tk.BOTH, side=tk.LEFT, padx=5, pady=5)

            label = tk.Label(frame, text=f"{source} Data:")
            label.pack()

            text_area = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=30, height=10)
            text_area.pack(expand=True, fill=tk.BOTH)
            self.text_areas[source] = text_area

    def create_export_options(self):
        export_frame = tk.Frame(self.master)
        export_frame.pack(side=tk.BOTTOM, padx=10, pady=10)

        file_label = tk.Label(export_frame, text="File Name:")
        file_label.pack()

        self.file_entry = tk.Entry(export_frame)
        self.file_entry.pack()

        filetype_label = tk.Label(export_frame, text="File Type:")
        filetype_label.pack()

        self.filetype_var = tk.StringVar(self.master)
        filetype_menu = tk.OptionMenu(export_frame, self.filetype_var, ".txt", ".csv")
        filetype_menu.pack()

        sources_label = tk.Label(export_frame, text="Select Sources:")
        sources_label.pack()

        self.sources_var = tk.StringVar(self.master)
        sources_menu = tk.OptionMenu(export_frame, self.sources_var, *["Transceiver1", "Transceiver2", "ADC"])
        sources_menu.pack()

        export_button = tk.Button(export_frame, text="Export", command=self.export_data)
        export_button.pack()

    def start_socket_server(self):
        self.socket_server_thread = threading.Thread(target=self.socket_server)
        self.socket_server_thread.start()

    def socket_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('0.0.0.0', 12345))  # Use any available port
        server_socket.listen(1)

        print("Socket server started, waiting for connections...")

        while True:
            client_socket, addr = server_socket.accept()
            print("Connected by", addr)

            # Receive CAN frames from client
            while True:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break

                    # Process received CAN frame
                    self.process_can_frame(data)
                except Exception as e:
                    print("Error receiving CAN frame:", e)

            client_socket.close()

    def process_can_frame(self, data):
        try:
            # Unpack the received data
            can_id, can_data = struct.unpack("<LL", data[:8])
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Determine the source of the CAN frame based on its CAN ID
            source = None
            if can_id == 0x123:
                source = "Transceiver1"
            elif can_id == 0x456:
                source = "Transceiver2"
            elif can_id == 0x789:
                source = "ADC"

            # Update the corresponding text area in the GUI with the received information
            if source:
                self.text_areas[source].insert(tk.END, f"{timestamp} - CAN ID: {hex(can_id)}, Data: {hex(can_data)}\n")
            else:
                print("Unknown CAN ID:", hex(can_id))
        except struct.error as e:
            print("Error unpacking CAN frame data:", e)

    def export_data(self):
        selected_source = self.sources_var.get()
        if not selected_source:
            messagebox.showerror("Error", "Please select a data source.")
            return

        file_name = self.file_entry.get()
        file_type = self.filetype_var.get()
        file_path = filedialog.asksaveasfilename(defaultextension=file_type, initialfile=file_name)
        if file_path:
            with open(file_path, 'w') as f:
                for source in self.received_data:
                    if source == selected_source:
                        f.write(f"{source} Data:\n")
                        f.writelines([f"{line}\n" for line in self.text_areas[source].get('1.0', tk.END).split('\n') if
                                      line.strip()])
            messagebox.showinfo("Export Successful", "Data exported successfully.")

def main():
    root = tk.Tk()
    app = CANFrameReceiverGUI(root)
    root.configure(background='#87CEEB')  # Set background color to blue
    root.mainloop()

if __name__ == "__main__":
    main()
