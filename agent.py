import time
import psutil
import requests
import os

SERVER_URL = "http://localhost:5000/api/report"
INTERVAL = 3 # seconds

process_cache = {}

def collect_metrics():
    global process_cache
    # Overall CPU usage (blocking call for 0.5s to get accurate reading)
    cpu_percent = psutil.cpu_percent(interval=0.5)
    
    # Overall memory usage
    memory = psutil.virtual_memory()
    memory_percent = memory.percent
    
    # Process metrics
    processes = []
    suspicious_keywords = ["miner", "xmrig", "cryptonight", "hash", "cpuminer", "minerd", "ethminer", "stratum"]
    
    current_pids = set()
    
    for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
        try:
            info = proc.info
            pid = info['pid']
            name = info['name']
            
            # Exclude System Idle Process (idle time reporter)
            if pid == 0 or (name or "").lower() == "system idle process":
                continue
                
            mem_p = info['memory_percent'] or 0.0

            current_pids.add(pid)
            
            # Retrieve or cache Process object to maintain CPU usage baseline
            if pid in process_cache:
                p_obj = process_cache[pid]
            else:
                p_obj = proc
                # Prime the CPU tracker on the first sighting
                try:
                    p_obj.cpu_percent(interval=None)
                except:
                    pass
                process_cache[pid] = p_obj
                
            try:
                cpu_p = p_obj.cpu_percent(interval=None)
            except:
                cpu_p = 0.0
                
            # Normalize CPU usage for multi-core systems
            cpu_p = cpu_p / psutil.cpu_count()
            
            processes.append({
                "pid": pid,
                "name": name,
                "cpu_percent": round(cpu_p, 2),
                "memory_percent": round(mem_p, 2),
                "is_suspicious_name": any(kw in (name or "").lower() for kw in suspicious_keywords)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
            
    # Purge cache entries for processes that have terminated
    process_cache = {pid: obj for pid, obj in process_cache.items() if pid in current_pids}
    
    # Sort processes by CPU usage descending
    processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
    
    # Keep top 15 CPU consuming processes, plus any that have suspicious names
    top_processes = processes[:15]
    top_pids = {p['pid'] for p in top_processes}
    
    for p in processes[15:]:
        if p['is_suspicious_name'] and p['pid'] not in top_pids:
            top_processes.append(p)
            
    return {
        "timestamp": time.time(),
        "cpu_percent": cpu_percent,
        "memory_percent": memory_percent,
        "processes": top_processes
    }


def main():
    print("Starting Cryptojacking Monitoring Agent...")
    print(f"Reporting to: {SERVER_URL}")
    print(f"Interval: {INTERVAL} seconds")
    
    # Prime psutil process cpu percent measurements (first call returns 0.0)
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(interval=None)
        except:
            pass
            
    time.sleep(1) # Let processes accumulate some CPU ticks
    
    while True:
        try:
            data = collect_metrics()
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Collected data: CPU {data['cpu_percent']}% | Memory {data['memory_percent']}% | Processes: {len(data['processes'])}")
            
            # Send to server
            response = requests.post(SERVER_URL, json=data, timeout=5)
            if response.status_code == 200:
                print("Successfully sent report to server.")
            else:
                print(f"Server returned error code: {response.status_code}")
        except requests.exceptions.ConnectionError:
            print("Could not connect to server. Retrying in next interval...")
        except Exception as e:
            print(f"Error collecting or sending metrics: {e}")
            
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
