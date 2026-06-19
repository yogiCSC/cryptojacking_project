import sqlite3
import os
db_path = r"C:\Users\VINUTHA VARUN\.gemini\antigravity\scratch\cryptojacking-detector\cryptojack.db"
if not os.path.exists(db_path):
    print("Database file does not exist yet.")
else:
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT * FROM telemetry_logs ORDER BY id DESC LIMIT 5")
    print("Latest telemetry logs (ID, Timestamp, CPU%, Mem%, TopProcName, TopProcPID, TopProcCPU%, TopProcMem%, SuspiciousCount, NumProcesses, IsAnomaly, Label):")
    for row in c.fetchall():
        print(row)
    c.execute("SELECT * FROM alerts")
    print("\nAlerts (ID, Timestamp, TriggerPID, TriggerProcName, CPUUsage, Resolved, ResolvedTime):")
    for row in c.fetchall():
        print(row)
    conn.close()
