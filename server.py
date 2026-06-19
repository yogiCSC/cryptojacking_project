import os
import sqlite3
import time
import pickle
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify, render_template
from sklearn.ensemble import IsolationForest, RandomForestClassifier
import threading

app = Flask(__name__, template_folder='templates', static_folder='static')
DB_PATH = 'cryptojack.db'
MODEL_DIR = 'models'
IF_MODEL_PATH = os.path.join(MODEL_DIR, 'isolation_forest.pkl')
RF_MODEL_PATH = os.path.join(MODEL_DIR, 'random_forest.pkl')

# Global variables for models and system state
models_lock = threading.Lock()
if_model = None
rf_model = None
model_status = "Untrained (Using Heuristics)"
latest_report = None
consecutive_normal_reports = 0

# Ensure directories exist
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS telemetry_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            cpu_percent REAL,
            memory_percent REAL,
            highest_proc_name TEXT,
            highest_proc_pid INTEGER,
            highest_proc_cpu REAL,
            highest_proc_mem REAL,
            suspicious_names_count INTEGER,
            num_processes INTEGER,
            is_anomaly INTEGER,
            cryptojack_label INTEGER
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            trigger_pid INTEGER,
            trigger_process_name TEXT,
            cpu_usage REAL,
            resolved INTEGER,
            resolved_time REAL
        )
    ''')
    conn.commit()
    conn.close()

def load_models():
    global if_model, rf_model, model_status
    with models_lock:
        if os.path.exists(IF_MODEL_PATH) and os.path.exists(RF_MODEL_PATH):
            try:
                with open(IF_MODEL_PATH, 'rb') as f:
                    if_model = pickle.load(f)
                with open(RF_MODEL_PATH, 'rb') as f:
                    rf_model = pickle.load(f)
                model_status = "Trained (Ready)"
                print("Models loaded successfully.")
            except Exception as e:
                model_status = "Error loading models"
                print(f"Error loading models: {e}")
        else:
            model_status = "Untrained (Using Heuristics)"

def rule_based_classify(report):
    # Rule-based heuristics for cryptojacking detection (fallback & bootstrapping)
    # 1. Any process containing cryptominer keywords using > 15% CPU
    # 2. Overall CPU usage > 75% and the top process is using > 40% CPU
    # 3. Any single process using > 70% CPU (normalized)
    cpu_percent = report.get('cpu_percent', 0)
    processes = report.get('processes', [])
    
    if not processes:
        return 0, None
        
    top_proc = processes[0]
    
    # Check for suspicious name keywords
    for proc in processes:
        if proc.get('is_suspicious_name', False) and proc.get('cpu_percent', 0) > 5.0:
            return 1, proc
            
    if cpu_percent > 75.0 and top_proc.get('cpu_percent', 0) > 40.0:
        return 1, top_proc
        
    for proc in processes:
        if proc.get('cpu_percent', 0) > 70.0:
            return 1, proc
            
    return 0, None

def predict_report(report):
    global if_model, rf_model
    
    # Run heuristic first (important for bootstrapping/immediate safety)
    h_label, h_proc = rule_based_classify(report)
    
    processes = report.get('processes', [])
    top_proc = processes[0] if processes else {"name": "None", "pid": 0, "cpu_percent": 0.0, "memory_percent": 0.0}
    suspicious_count = sum(1 for p in processes if p.get('is_suspicious_name', False))
    
    # Model features
    features = [
        report.get('cpu_percent', 0),
        report.get('memory_percent', 0),
        top_proc.get('cpu_percent', 0),
        top_proc.get('memory_percent', 0),
        suspicious_count,
        len(processes)
    ]
    
    # Check if models are available for prediction
    with models_lock:
        if if_model is not None and rf_model is not None:
            try:
                X = np.array([features])
                # Isolation Forest predicts -1 for anomaly, 1 for normal
                anomaly_pred = if_model.predict(X)[0]
                # Random Forest predicts 0 (Normal) or 1 (Cryptojack)
                rf_pred = rf_model.predict(X)[0]
                rf_prob = rf_model.predict_proba(X)[0][1]
                
                is_anomalous_if = (anomaly_pred == -1)
                
                # Determine trigger process (usually the top CPU or a suspicious one with significant CPU)
                trigger_proc = top_proc
                for proc in processes:
                    if proc.get('cpu_percent', 0) > 20.0 and (proc.get('is_suspicious_name', False) or proc.get('cpu_percent', 0) > trigger_proc.get('cpu_percent', 0)):
                        trigger_proc = proc
                
                # Final decision logic combining RF probability and Isolation Forest anomaly score
                if rf_prob > 0.6 or (is_anomalous_if and rf_prob > 0.4):
                    return 1, trigger_proc, float(rf_prob), is_anomalous_if
                else:
                    return 0, None, float(rf_prob), is_anomalous_if
            except Exception as e:
                print(f"Error during ML prediction: {e}")
                return h_label, h_proc, 0.0, False
        else:
            return h_label, h_proc, 0.0, False

def save_telemetry_and_check_alerts(report, label, trigger_proc, is_anomaly_flag, rf_prob):
    global consecutive_normal_reports
    
    processes = report.get('processes', [])
    top_proc = processes[0] if processes else {"name": "None", "pid": 0, "cpu_percent": 0.0, "memory_percent": 0.0}
    suspicious_count = sum(1 for p in processes if p.get('is_suspicious_name', False))
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Save log
    c.execute('''
        INSERT INTO telemetry_logs (
            timestamp, cpu_percent, memory_percent, highest_proc_name, 
            highest_proc_pid, highest_proc_cpu, highest_proc_mem, 
            suspicious_names_count, num_processes, is_anomaly, cryptojack_label
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        report.get('timestamp', time.time()), 
        report.get('cpu_percent', 0), 
        report.get('memory_percent', 0),
        top_proc.get('name', ''), 
        top_proc.get('pid', 0), 
        top_proc.get('cpu_percent', 0), 
        top_proc.get('memory_percent', 0),
        suspicious_count, 
        len(processes), 
        1 if is_anomaly_flag else 0, 
        label
    ))
    conn.commit()
    
    # Alert lifecycle management
    if label == 1:
        consecutive_normal_reports = 0
        
        # Check if there is an active (unresolved) alert
        c.execute("SELECT id FROM alerts WHERE resolved = 0")
        active_alert = c.fetchone()
        
        if not active_alert and trigger_proc:
            # Create a new alert
            c.execute('''
                INSERT INTO alerts (timestamp, trigger_pid, trigger_process_name, cpu_usage, resolved, resolved_time)
                VALUES (?, ?, ?, ?, 0, NULL)
            ''', (report.get('timestamp', time.time()), trigger_proc.get('pid', 0), trigger_proc.get('name', ''), trigger_proc.get('cpu_percent', 0)))
            conn.commit()
            print(f"ALERT TRIGGERED: Cryptojacking detected in PID {trigger_proc.get('pid')} ({trigger_proc.get('name')})")
    else:
        consecutive_normal_reports += 1
        if consecutive_normal_reports >= 3:
            # Auto-resolve alert after 3 consecutive normal intervals
            c.execute("SELECT id FROM alerts WHERE resolved = 0")
            active_alerts = c.fetchall()
            if active_alerts:
                c.execute("UPDATE alerts SET resolved = 1, resolved_time = ? WHERE resolved = 0", (time.time(),))
                conn.commit()
                print("ALERT RESOLVED: System returned to normal behavior.")
                
    conn.close()

def train_models_task():
    global if_model, rf_model, model_status
    model_status = "Training..."
    
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM telemetry_logs", conn)
        conn.close()
        
        if len(df) < 10:
            model_status = "Failed (Need >= 10 logs)"
            print("Training failed: Not enough data points in DB.")
            return
            
        X = df[['cpu_percent', 'memory_percent', 'highest_proc_cpu', 'highest_proc_mem', 'suspicious_names_count', 'num_processes']].values
        
        # Fit Isolation Forest (Unsupervised Anomaly Detection)
        if_model_new = IsolationForest(contamination=0.08, random_state=42)
        if_model_new.fit(X)
        
        # Auto-generate labels for Random Forest based on rule logic applied to DB logs
        y = []
        for _, row in df.iterrows():
            is_cj = row['cryptojack_label']
            # Re-apply strict conditions for training labels
            if row['cpu_percent'] > 75.0 and row['highest_proc_cpu'] > 40.0:
                is_cj = 1
            if row['highest_proc_cpu'] > 70.0:
                is_cj = 1
            if row['suspicious_names_count'] > 0 and row['highest_proc_cpu'] > 15.0:
                is_cj = 1
            y.append(is_cj)
            
        y = np.array(y)
        
        # Handle case where only 1 class exists in training data
        if len(np.unique(y)) < 2:
            # Inject synthetic normal and cryptominer rows to guarantee binary classes are present
            X = np.vstack([X, [10.0, 30.0, 5.0, 1.0, 0, 10]])
            y = np.append(y, [0])
            X = np.vstack([X, [90.0, 80.0, 85.0, 4.0, 1, 15]])
            y = np.append(y, [1])
            
        rf_model_new = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_model_new.fit(X, y)
        
        # Save models to file system
        with open(IF_MODEL_PATH, 'wb') as f:
            pickle.dump(if_model_new, f)
        with open(RF_MODEL_PATH, 'wb') as f:
            pickle.dump(rf_model_new, f)
            
        with models_lock:
            if_model = if_model_new
            rf_model = rf_model_new
            model_status = f"Trained (Logs: {len(df)})"
            
        print("Models successfully trained and updated.")
    except Exception as e:
        model_status = f"Training failed: {str(e)}"
        print(f"Error during model training: {e}")

# HTTP Routing & API endpoints

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/report', methods=['POST'])
def receive_report():
    global latest_report
    report = request.json
    if not report:
        return jsonify({"error": "Invalid payload"}), 400
        
    latest_report = report
    
    # Run classification prediction
    label, trigger_proc, rf_prob, is_anomaly_flag = predict_report(report)
    
    # Save log and update alert statuses
    save_telemetry_and_check_alerts(report, label, trigger_proc, is_anomaly_flag, rf_prob)
    
    return jsonify({
        "status": "success",
        "cryptojacking_detected": bool(label == 1),
        "anomaly_flag": bool(is_anomaly_flag),
        "risk_score": round(rf_prob, 3)
    })

@app.route('/api/status', methods=['GET'])
def get_status():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Get active alert
    c.execute("SELECT * FROM alerts WHERE resolved = 0 ORDER BY timestamp DESC LIMIT 1")
    active_row = c.fetchone()
    
    active_alert = None
    if active_row:
        active_alert = {
            "id": active_row[0],
            "timestamp": active_row[1],
            "pid": active_row[2],
            "process_name": active_row[3],
            "cpu_usage": active_row[4]
        }
        
    # Get database log count
    c.execute("SELECT COUNT(*) FROM telemetry_logs")
    log_count = c.fetchone()[0]
    conn.close()
    
    is_secure = (active_alert is None)
    
    # Fetch current stats
    cpu = latest_report.get('cpu_percent', 0.0) if latest_report else 0.0
    memory = latest_report.get('memory_percent', 0.0) if latest_report else 0.0
    
    return jsonify({
        "is_secure": is_secure,
        "status_text": "SECURE" if is_secure else "CRYPTOJACKER DETECTED",
        "cpu_percent": cpu,
        "memory_percent": memory,
        "active_alert": active_alert,
        "model_status": model_status,
        "log_count": log_count
    })

@app.route('/api/processes', methods=['GET'])
def get_processes():
    if not latest_report:
        return jsonify([])
        
    # Enrich process list with indicator tags
    processes = latest_report.get('processes', [])
    enriched_processes = []
    
    for p in processes:
        risk_score = 0.0
        # Quick rule indicator
        if p.get('cpu_percent', 0) > 40.0:
            risk_score += 0.4
        if p.get('is_suspicious_name', False):
            risk_score += 0.5
        if p.get('cpu_percent', 0) > 70.0:
            risk_score += 0.4
            
        enriched_processes.append({
            "pid": p.get('pid'),
            "name": p.get('name'),
            "cpu_percent": p.get('cpu_percent'),
            "memory_percent": p.get('memory_percent'),
            "is_suspicious_name": p.get('is_suspicious_name'),
            "risk_score": min(risk_score, 1.0)
        })
        
    return jsonify(enriched_processes)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    
    alerts = []
    for r in rows:
        alerts.append({
            "id": r['id'],
            "timestamp": r['timestamp'],
            "pid": r['trigger_pid'],
            "process_name": r['trigger_process_name'],
            "cpu_usage": r['cpu_usage'],
            "resolved": bool(r['resolved']),
            "resolved_time": r['resolved_time']
        })
    return jsonify(alerts)

@app.route('/api/train', methods=['POST'])
def run_train():
    t = threading.Thread(target=train_models_task)
    t.start()
    return jsonify({"status": "training_started", "message": "Training job dispatched."})

@app.route('/api/clear_alerts', methods=['POST'])
def clear_alerts():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE alerts SET resolved = 1, resolved_time = ? WHERE resolved = 0", (time.time(),))
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "All alerts cleared and resolved."})

if __name__ == '__main__':
    print("Initializing Database...")
    init_db()
    print("Loading AI models...")
    load_models()
    print("Starting server on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
