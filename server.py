from flask import Flask
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP, Ether
import pandas as pd
import numpy as np
import joblib
import threading
import time
import os
from collections import defaultdict

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# --- 1. MODEL YÜKLEME VE SINIF TANIMI ---
class NetworkGuardSystem:
    def __init__(self, binary_model, expert_model, feature_list):
        self.gatekeeper = binary_model
        self.expert = expert_model
        self.features = feature_list
        self.expert_labels = {0: 'DoS/DDoS', 1: 'PortScan', 2: 'BruteForce', 3: 'Web Attack', 4: 'Botnet'}

    def process_packet(self, packet_row):
        try:
            # Eksik özellik doldurma (Aynen kalsın)
            for f in self.features:
                if f not in packet_row.columns: packet_row[f] = 0.0
            packet_features = packet_row[self.features]
        except Exception as e:
            return "HATA", "System", 0.0

        # --- GÜNCELLEME BURADA ---
        # Eskisi: is_attack = self.gatekeeper.predict(packet_features)[0]
        
        # Yenisi: Olasılıkları alalım [Normal_Olasılığı, Saldırı_Olasılığı]
        probs = self.gatekeeper.predict_proba(packet_features)[0]
        attack_probability = probs[1] # 1. indeks saldırı ihtimalidir

        # EŞİK DEĞERİ (THRESHOLD): %40
        # Eğer saldırı ihtimali %40'tan fazlaysa, riske atma, Uzmana sor!
        if attack_probability > 0.40:
            # 2. Uzman Analizi
            attack_code = self.expert.predict(packet_features)[0]
            attack_name = self.expert_labels.get(attack_code, "Unknown")
            confidence = float(self.expert.predict_proba(packet_features).max() * 100)
            
            # Eğer Uzman da çok düşük güvenle cevap verirse, o zaman Normal diyebiliriz
            # Ama şimdilik her şeyi görelim
            return attack_name, "Expert Model", confidence
        else:
            return "NORMAL", "Gatekeeper", 100.0

# Modeli Yükle
MODEL_PATH = [f for f in os.listdir('.') if f.endswith('.pkl') and 'NetworkGuard' in f]
system_instance = None
required_features = []

if MODEL_PATH:
    try:
        print(f"📡 Model Yükleniyor: {MODEL_PATH[-1]}...")
        loaded_package = joblib.load(MODEL_PATH[-1])
        system_instance = loaded_package['system_object']
        required_features = loaded_package['features']
        print(f"✅ Model Hazır! ({len(required_features)} özellik)")
    except Exception as e:
        print(f"❌ Model Hatası: {e}")
        exit()

# --- 2. AKIŞ TAKİPÇİSİ (FLOW TRACKER) ---
# Scapy'den gelen ham paketleri, modelin anladığı istatistiklere çevirir.
class FlowSession:
    def __init__(self):
        self.flows = defaultdict(lambda: {
            'start_time': 0,
            'last_time': 0,
            'packet_count': 0,
            'total_bytes': 0,
            'iat_list': []
        })
    
    def update_flow(self, src_ip, dst_ip, src_port, dst_port, protocol, length, timestamp):
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        flow = self.flows[flow_key]
        
        if flow['packet_count'] == 0:
            flow['start_time'] = timestamp
            flow['last_time'] = timestamp
        else:
            iat = (timestamp - flow['last_time']) * 1000000
            flow['iat_list'].append(iat)
            flow['last_time'] = timestamp

        flow['packet_count'] += 1
        flow['total_bytes'] += length
        
        # --- İYİLEŞTİRME 1: Sıfıra Bölünme ve Aşırı Değer Koruması ---
        duration = timestamp - flow['start_time']
        
        # Eğer süre çok kısaysa (0.1 sn altı), bunu yapay olarak 0.1 kabul et
        # Bu, "Flow Bytes/s" değerinin milyarlara fırlamasını engeller ve güveni artırır.
        safe_duration = max(duration, 0.1) 
        
        stats = {
            'Flow Duration': duration * 1000000,
            'Total Fwd Packets': flow['packet_count'],
            'Flow Bytes/s': flow['total_bytes'] / safe_duration,   # Düzeltildi
            'Flow Packets/s': flow['packet_count'] / safe_duration, # Düzeltildi
            'Flow IAT Mean': np.mean(flow['iat_list']) if flow['iat_list'] else 0,
            'Flow IAT Std': np.std(flow['iat_list']) if flow['iat_list'] else 0,
            'Flow IAT Max': np.max(flow['iat_list']) if flow['iat_list'] else 0,
            'Flow IAT Min': np.min(flow['iat_list']) if flow['iat_list'] else 0,
            'Fwd Packet Length Max': length, 
            'Fwd Packet Length Min': length,
            'Fwd Packet Length Mean': length,
             # ... Diğerleri 0
             'Bwd Packet Length Max': 0, 'Bwd Packet Length Min': 0, 'Bwd Packet Length Mean': 0,
             'Total Backward Packets': 0
        }
        return stats

session = FlowSession()

# --- 3. SCAPY DİNLEYİCİSİ ---
def packet_callback(packet):
    if IP in packet and (TCP in packet or UDP in packet):
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # --- İYİLEŞTİRME 2: BEYAZ LİSTE (WHITELIST) ---
            # Gereksiz gürültüyü (False Positive) engelle
            
            # 1. Multicast Trafiği (224.x.x.x) - Genelde zararsızdır
            if dst_ip.startswith("224.") or src_ip.startswith("224."): return
            if dst_ip.startswith("239.") or src_ip.startswith("239."): return
            if dst_ip == "255.255.255.255": return # Broadcast

            # 2. Protokol Filtresi
            if UDP in packet:
                # DNS (53), DHCP (67/68), NTP (123), SSDP (1900), MDNS (5353)
                # Bu portlar ev ağlarında çok gürültü yapar, saldırı değilse yoksayalım.
                ignore_ports = {53, 67, 68, 123, 1900, 5353}
                if packet[UDP].sport in ignore_ports or packet[UDP].dport in ignore_ports:
                    return

            length = len(packet)
            timestamp = time.time()
            
            # Protokol ve Bayrak Çıkarımı (Aynen Kalıyor)
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                proto = 6
                flags = packet[TCP].flags
                fin_flag = 1 if 'F' in flags else 0
                syn_flag = 1 if 'S' in flags else 0
                rst_flag = 1 if 'R' in flags else 0
                psh_flag = 1 if 'P' in flags else 0
                ack_flag = 1 if 'A' in flags else 0
                urg_flag = 1 if 'U' in flags else 0
            else:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                proto = 17
                fin_flag=syn_flag=rst_flag=psh_flag=ack_flag=urg_flag=0

            # Akış Hesapla
            flow_stats = session.update_flow(src_ip, dst_ip, src_port, dst_port, proto, length, timestamp)
            
            # Bayrakları Ekle
            flow_stats['FIN Flag Count'] = fin_flag
            flow_stats['SYN Flag Count'] = syn_flag
            flow_stats['RST Flag Count'] = rst_flag
            flow_stats['PSH Flag Count'] = psh_flag
            flow_stats['ACK Flag Count'] = ack_flag
            flow_stats['URG Flag Count'] = urg_flag
            flow_stats['Down/Up Ratio'] = 0

            # Tahmin
            df_packet = pd.DataFrame([flow_stats])
            label, source, conf = system_instance.process_packet(df_packet)
            
            # --- İYİLEŞTİRME 3: Güven Skoru Kalibrasyonu ---
            # Eğer model %50-%60 arasında kararsızsa ve Gatekeeper "Normal" dediyse,
            # bunu kullanıcıya yansıtma. Sadece yüksek güvenli saldırıları göster.
            
            if label != "NORMAL" and conf < 75.0:
                 # Güven %65 altındaysa "Şüpheli" de ama alarm çalma veya Normal kabul et
                 # Biz şimdilik Normal kabul edelim ki kafa karışmasın
                 label = "NORMAL"

            packet_data = {
                'id': int(time.time() * 100000) + random.randint(0,1000),
                'timestamp': time.strftime("%H:%M:%S"),
                'destinationPort': int(dst_port),
                'flowBytesSec': float(flow_stats['Flow Bytes/s']),
                'flowPacketsSec': float(flow_stats['Flow Packets/s']),
                'avgPacketSize': float(length),
                'label': label,
                'source_model': source,
                'confidence': conf
            }
            
            if label != "NORMAL":
                print(f"🚨 TESPİT: {label} (%{conf:.1f}) -> {src_ip}:{src_port}")
            
            socketio.emit('new_packet', packet_data)
            
        except Exception as e:
            pass

def start_sniffing():
    print("🦈 Scapy Başlatıldı! Ağ dinleniyor...")
    # iface=None derseniz varsayılan ağ kartını dinler.
    # Windows'ta bazen iface ismini belirtmek gerekebilir.
    from scapy.all import conf
    conf.iface = "Wi-Fi"
    sniff(prn=packet_callback, store=False)

    


# Sniffer'ı ayrı thread'de başlat
import random # ID için
threading.Thread(target=start_sniffing, daemon=True).start()

if __name__ == '__main__':
    # Flask sunucuyu başlat
    print("🌍 Web Sunucu Başlatılıyor: http://localhost:5000")
    socketio.run(app, port=5000)