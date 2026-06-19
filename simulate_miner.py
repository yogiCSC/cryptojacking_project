import sys
import os
import shutil
import subprocess
import time
import argparse
from threading import Thread
import multiprocessing

def cpu_workload():
    # Simple loop that consumes CPU
    import hashlib
    data = b"mining_simulation_data_to_hash_continuously"
    while True:
        # Perform SHA256 hashes in a loop to generate sustained CPU stress
        hashlib.sha256(data).hexdigest()

def main():
    parser = argparse.ArgumentParser(description="Cryptominer Simulator")
    parser.add_argument("--cores", type=int, default=2, help="Number of CPU cores to stress")
    parser.add_argument("--rename", action="store_true", help="Rename the process to simulate a real miner name")
    parser.add_argument("--active", action="store_true", help="Internal flag: running active miner workload")
    args = parser.parse_args()

    if args.rename and not args.active:
        # Create a copy of the Python executable named xmrig_miner.exe
        current_exe = sys.executable
        target_exe_name = "xmrig_miner.exe"
        target_exe_path = os.path.join(os.getcwd(), target_exe_name)
        
        print(f"Copying python executable to: {target_exe_path}")
        try:
            shutil.copy2(current_exe, target_exe_path)
        except Exception as e:
            print(f"Warning: Could not copy executable: {e}")
            target_exe_path = current_exe
            
        print(f"Relaunching miner simulation as '{target_exe_name}'...")
        # Start the process and wait for it
        cmd = [target_exe_path, __file__, "--active", "--cores", str(args.cores)]
        try:
            # On Windows, python exe might run without consoles depending on how it's called, Popen is safe
            p = subprocess.Popen(cmd)
            p.wait()
        except KeyboardInterrupt:
            print("\nStopping simulated miner...")
            p.terminate()
            p.wait()
        finally:
            # Clean up the exe if possible
            time.sleep(1)
            try:
                if os.path.exists(target_exe_path) and target_exe_path != current_exe:
                    os.remove(target_exe_path)
            except Exception as ex:
                print(f"Could not clean up {target_exe_name}: {ex}")
        return

    # If running the active workload
    cores_to_use = min(args.cores, multiprocessing.cpu_count())
    print(f"\n=== Cryptojacking Simulation Active ===")
    print(f"Process Name: {os.path.basename(sys.executable)}")
    print(f"Process PID: {os.getpid()}")
    print(f"Stressing {cores_to_use} CPU cores...")
    
    threads = []
    for i in range(cores_to_use):
        t = Thread(target=cpu_workload, daemon=True)
        t.start()
        threads.append(t)
        print(f"Started miner thread {i+1}...")
        
    print("Mining started! Press Ctrl+C to stop.")
    
    # Fake miner output to look like a mining terminal
    hash_rate = 245.8
    try:
        while True:
            time.sleep(2.5)
            hash_rate += (time.time() % 3) - 1.5
            print(f"[{time.strftime('%H:%M:%S')}] speed: {hash_rate:.2f} H/s, shares: {int(time.time()/10)%100}/0/0, difficulty: 5000 (yaw)")
    except KeyboardInterrupt:
        print("\nStopping miner workload...")

if __name__ == "__main__":
    main()
