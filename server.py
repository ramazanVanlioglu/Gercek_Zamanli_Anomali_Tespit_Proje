from flask import Flask
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import numpy as np
import joblib
import threading
import time
import os
import random
from collections import defaultdict
import csv

app = Flask(__name__)
# React varsayılan olarak port 3000'de çalışır, CORS izni veriyoruz
socketio = SocketIO(app, cors_allowed_origins="*")

FLOW_TIMEOUT = 5.0
FLOW_CHECK_INTERVAL = 1.0
LOG_FILE = "traffic_logs.csv"

class NetworkGuardSystem:
    def __init__(self, binary_model, expert_model, feature_list):
        self.gatekeeper = binary_model
        self.expert = expert_model
        self.features = feature_list
        self.expert_labels = {0: 'DoS/DDoS', 1: 'PortScan', 2: 'BruteForce', 3: 'Web Attack', 4: 'Botnet'}

    def process_flow(self, flow_features_df):
        try:
            for f in self.features:
                if f not in flow_features_df.columns:
                    flow_features_df[f] = 0.0
            
            model_input = flow_features_df[self.features]
            probs = self.gatekeeper.predict_proba(model_input)[0]
            attack_prob = probs[1] 

            if attack_prob > 0.4: 
                attack_code = self.expert.predict(model_input)[0]
                attack_name = self.expert_labels.get(attack_code, "Unknown")
                confidence = float(self.expert.predict_proba(model_input).max() * 100)
                return attack_name, "Expert Model", confidence
            else:
                normal_confidence = float(probs[0] * 100)
                return "NORMAL", "Gatekeeper", normal_confidence
        except Exception as e:
            print(f"Model Hatası: {e}")
            return "HATA", "System", 0.0

MODEL_PATH = [f for f in os.listdir('.') if f.endswith('.pkl') and 'NetworkGuard' in f]
system_instance = None

if MODEL_PATH:
    try:
        print(f"Model Yükleniyor: {MODEL_PATH[-1]}...")
        loaded_package = joblib.load(MODEL_PATH[-1])
        system_instance = loaded_package['system_object']
        print(f"Model Hazır! CICIDS2017 Akış Moduna Geçildi.")
    except Exception as e:
        print(f"Model Yükleme Hatası: {e}")
        system_instance = DummyNetworkGuard()
else:
    print("UYARI: .pkl model dosyası bulunamadı.")
    system_instance = DummyNetworkGuard()

# --- 2. AKIŞ YÖNETİMİ ---
class FlowManager:
    def __init__(self):
        self.active_flows = {}
        self.lock = threading.Lock()
        
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Label", "Confidence"])

    def update(self, packet_info):
        key = packet_info['key']
        timestamp = packet_info['timestamp']
        length = packet_info['length']
        flags = packet_info['flags']

        with self.lock:
            if key not in self.active_flows:
                self.active_flows[key] = {
                    'start_time': timestamp,
                    'last_time': timestamp,
                    'packet_count': 0,
                    'total_bytes': 0,
                    'iat_list': [],
                    'flags': defaultdict(int),
                    'src_ip': key[0],
                    'dst_ip': key[1],
                    'src_port': key[2],
                    'dst_port': key[3],
                    'protocol': key[4]
                }
            
            flow = self.active_flows[key]
            
            if flow['packet_count'] > 0:
                iat = (timestamp - flow['last_time']) * 1_000_000
                flow['iat_list'].append(iat)

            flow['last_time'] = timestamp
            flow['packet_count'] += 1
            flow['total_bytes'] += length
            
            if flags:
                for flag in flags:
                    flow['flags'][flag] += 1

    def check_timeouts_and_predict(self):
        current_time = time.time()
        flows_to_process = []

        with self.lock:
            keys_to_remove = []
            for key, flow in self.active_flows.items():
                idle_time = current_time - flow['last_time']
                is_finished = False
                
                if 'F' in flow['flags'] or 'R' in flow['flags']:
                    is_finished = True
                elif idle_time > FLOW_TIMEOUT:
                    is_finished = True

                if is_finished:
                    flows_to_process.append(flow)
                    keys_to_remove.append(key)
            
            for k in keys_to_remove:
                del self.active_flows[k]

        for flow in flows_to_process:
            self._analyze_flow(flow)

    def _analyze_flow(self, flow):
        duration = max(flow['last_time'] - flow['start_time'], 0.001)
        
        features = {
            'Flow Duration': duration * 1_000_000,
            'Total Fwd Packets': flow['packet_count'],
            'Flow Bytes/s': flow['total_bytes'] / duration,
            'Flow Packets/s': flow['packet_count'] / duration,
            'Flow IAT Mean': np.mean(flow['iat_list']) if flow['iat_list'] else 0,
            'Flow IAT Std': np.std(flow['iat_list']) if flow['iat_list'] else 0,
            'Flow IAT Max': np.max(flow['iat_list']) if flow['iat_list'] else 0,
            'Flow IAT Min': np.min(flow['iat_list']) if flow['iat_list'] else 0,
            # (Diğer feature'lar buraya eklenebilir, şimdilik temel olanlar var)
        }

        # DataFrame oluştur ve tahmin al
        df = pd.DataFrame([features])
        # Eksik sütunları 0 ile doldur (Dummy veya Gerçek model için)
        if hasattr(system_instance, 'features'):
            for f in system_instance.features:
                if f not in df.columns:
                    df[f] = 0.0
                    
        label, source, conf = system_instance.process_flow(df)

        # Loglama
        try:
            with open(LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(flow['last_time'])),
                    flow['src_ip'], flow['src_port'], flow['dst_ip'], flow['dst_port'], flow['protocol'], label, f"{conf:.2f}"
                ])
        except Exception:
            pass

        if label != "NORMAL":
            print(f"!!! SALDIRI TESPİT EDİLDİ: {label} -> {flow['dst_ip']}")
        
        # --- REACT ARAYÜZÜNE VERİ GÖNDERME ---
        socketio.emit('new_packet', {
            'id': random.randint(10000, 999999),
            'time': time.strftime("%H:%M:%S", time.localtime(flow['last_time'])),
            'src': flow['src_ip'],
            'srcPort': flow['src_port'],   # React sol panel için gerekli
            'dst': flow['dst_ip'],
            'dstPort': flow['dst_port'],   # React sol panel için gerekli
            'flowBytes': float(features['Flow Bytes/s']),
            'label': label,
            'model': source,               # Gatekeeper / Expert
            'confidence': conf,
            'is_attack': label != "NORMAL"
        })

flow_manager = FlowManager()

# --- 3. PACKET SNIFFING ---
def packet_callback(packet):
    if IP in packet:
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Loopback ve Multicast trafiğini yok say
            if dst_ip == "127.0.0.1" or src_ip == "127.0.0.1": return
            if dst_ip.startswith("224.") or dst_ip.startswith("239."): return

            proto = 0; src_port = 0; dst_port = 0; flags = ""

            if TCP in packet:
                proto = 6
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
            elif UDP in packet:
                proto = 17
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                # Yaygın gürültü portlarını (DNS, SSDP) filtrele
                if src_port in [53, 5353, 1900] or dst_port in [53, 5353, 1900]: return

            key = (src_ip, dst_ip, src_port, dst_port, proto)
            
            packet_info = {
                'key': key,
                'timestamp': time.time(),
                'length': len(packet),
                'flags': str(flags)
            }
            flow_manager.update(packet_info)

        except Exception:
            pass

def flow_monitor_loop():
    print("Akış Denetleyicisi Başlatıldı...")
    while True:
        try:
            time.sleep(FLOW_CHECK_INTERVAL)
            flow_manager.check_timeouts_and_predict()
        except Exception as e:
            print(f"Monitor Error: {e}")

def start_sniffing():
    print("Scapy Dinlemeye Başladı...")
    sniff(prn=packet_callback, store=False)

if __name__ == '__main__':
    t_sniff = threading.Thread(target=start_sniffing, daemon=True)
    t_sniff.start()

    t_monitor = threading.Thread(target=flow_monitor_loop, daemon=True)
    t_monitor.start()

    print("Web Sunucu (SocketIO): http://localhost:5000")
    socketio.run(app, port=5000, allow_unsafe_werkzeug=True)
