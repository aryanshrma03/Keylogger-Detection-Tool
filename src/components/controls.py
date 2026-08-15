import customtkinter as ctk

def create_controls(parent, scan_command, json_command, normal_command, suspicious_command, reset_command):
    frame = ctk.CTkFrame(parent, fg_color="transparent")
    frame.pack(fill="x", padx=30, pady=8)

    ctk.CTkButton(frame, text="Run System Scan", command=scan_command,
                  width=135, height=42, corner_radius=10).pack(side="left")

    ctk.CTkButton(frame, text="Analyze JSON", command=json_command,
                  width=120, height=42, corner_radius=10).pack(side="left", padx=8)

    ctk.CTkButton(frame, text="Normal Simulation", command=normal_command,
                  width=150, height=42, corner_radius=10).pack(side="left")

    ctk.CTkButton(frame, text="Suspicious Simulation", command=suspicious_command,
                  width=165, height=42, corner_radius=10).pack(side="left", padx=8)

    ctk.CTkButton(frame, text="Reset", command=reset_command,
                  width=90, height=42, corner_radius=10,
                  fg_color="#3b3f46", hover_color="#4b5058").pack(side="right")
