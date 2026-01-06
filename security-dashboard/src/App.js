import React, { useState, useEffect, useRef } from 'react';
import io from 'socket.io-client';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';
import { AlertTriangle, ShieldAlert, Activity, Server, ArrowRight } from 'lucide-react';
import './App.css'; 

const COLORS = ['#EF4444', '#F59E0B', '#3B82F6', '#10B981', '#8B5CF6'];

// ==========================================
// 1. BİLEŞEN: ANA DASHBOARD (Girişten Sonra)
// ==========================================
const MainDashboard = () => {
  const [liveTrafficData, setLiveTrafficData] = useState([]);
  const [attackDistData, setAttackDistData] = useState([]);
  const [throughputData, setThroughputData] = useState([]);
  const [detectedAttacks, setDetectedAttacks] = useState([]);
  const [isUnderAttack, setIsUnderAttack] = useState(false);

  const socketRef = useRef(null);

  useEffect(() => {
    // Socket bağlantısı sadece giriş yapıldıktan sonra başlar
    socketRef.current = io('http://localhost:5000');

    socketRef.current.on('connect', () => {
      console.log("Backend sunucusuna bağlanıldı!");
    });

    socketRef.current.on('new_packet', (data) => {
      handleNewData(data);
    });

    return () => {
      socketRef.current.disconnect();
    };
  }, []);

  const handleNewData = (data) => {
    // A) Sol Panel
    setLiveTrafficData((prev) => {
      const newList = [data, ...prev];
      return newList.slice(0, 20);
    });

    // B) Sağ Üst Grafik
    setThroughputData((prev) => {
      const newPoint = { time: data.time, bytes: data.flowBytes };
      const newList = [...prev, newPoint];
      return newList.length > 20 ? newList.slice(newList.length - 20) : newList;
    });

    // C) Saldırı Tespit Edilirse
    if (data.is_attack) {
      triggerAttackAlert();
      
      setDetectedAttacks((prev) => [data, ...prev]);

      setAttackDistData((prev) => {
        const existingIndex = prev.findIndex(item => item.name === data.label);
        
        if (existingIndex >= 0) {
          const newArr = [...prev];
          newArr[existingIndex] = { 
            ...newArr[existingIndex], 
            value: newArr[existingIndex].value + 1 
          };
          return newArr;
        } else {
          return [...prev, { name: data.label, value: 1 }];
        }
      });
    }
  };

  const triggerAttackAlert = () => {
    setIsUnderAttack(true);
    setTimeout(() => setIsUnderAttack(false), 3000);
  };

  return (
    <div className={`app-container ${isUnderAttack ? 'alert-mode' : ''}`}>
      
      {/* HEADER */}
      <header className="header">
        <div className="header-title">
          <ShieldAlert color="#60a5fa" />
          AI Güvenlik Monitörü (Canlı)
        </div>
        {isUnderAttack && (
          <div className="alert-badge">
            <AlertTriangle size={18} /> SALDIRI TESPİT EDİLDİ!
          </div>
        )}
      </header>

      {/* GÖVDE */}
      <div className="dashboard-body">
        
        {/* SOL PANEL */}
        <aside className="sidebar">
          <h3 className="panel-title">
            <Activity size={18} /> Canlı Trafik Akışı
          </h3>
          <div className="flow-list">
            {liveTrafficData.map((flow) => (
              <div key={flow.id} className="flow-card">
                <div className="flow-header">
                  <span>{flow.time}</span>
                  <span className={flow.label === 'NORMAL' ? 'label-normal' : 'label-attack'}>
                    {flow.label}
                  </span>
                </div>
                <div className="flow-details">
                  <span style={{ color: '#93c5fd' }}>{flow.src}:{flow.srcPort}</span>
                  <ArrowRight size={12} />
                  <span style={{ color: '#a5b4fc' }}>{flow.dst}:{flow.dstPort}</span>
                </div>
                <div className="flow-meta">
                  <span>Flow: {Math.round(flow.flowBytes)} B/s</span>
                  <span className="model-badge">{flow.model}</span>
                </div>
              </div>
            ))}
            {liveTrafficData.length === 0 && (
              <div style={{padding: 20, textAlign: 'center', color: '#64748b'}}>Veri bekleniyor...</div>
            )}
          </div>
        </aside>

        {/* SAĞ TARAF */}
        <main className="main-content">
          
          {/* ÜST GRAFİKLER */}
          <div className="charts-section">
            <div className="chart-box">
              <h3 className="panel-title" style={{background: 'transparent', padding: '0 0 10px 0'}}>Saldırı Dağılımı</h3>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={attackDistData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                    {attackDistData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#fff' }} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
              {attackDistData.length === 0 && (
                 <div style={{textAlign: 'center', color: '#64748b', fontSize: '0.8rem'}}>Henüz saldırı tespit edilmedi.</div>
              )}
            </div>

            <div className="chart-box">
              <h3 className="panel-title" style={{background: 'transparent', padding: '0 0 10px 0'}}>Throughput (Bytes/s)</h3>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={throughputData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="time" stroke="#94a3b8" />
                  <YAxis stroke="#94a3b8" />
                  <Tooltip contentStyle={{ backgroundColor: '#1e293b', borderColor: '#334155', color: '#fff' }} />
                  <Line type="monotone" dataKey="bytes" stroke="#8884d8" strokeWidth={2} dot={false} isAnimationActive={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* ALT LİSTE */}
          <div className="attacks-section">
            <h3 className="panel-title" style={{background: 'transparent', padding: '0 0 10px 0', color: '#f87171'}}>
               <Server size={16} /> Yakalanan Saldırılar
            </h3>
            <div className="attacks-table-wrapper">
              <table className="attacks-table">
                <thead>
                  <tr>
                    <th>Saldırı Tipi</th>
                    <th>Kaynak</th>
                    <th>Hedef</th>
                    <th>Zaman</th>
                    <th>Güven Skoru</th>
                  </tr>
                </thead>
                <tbody>
                  {detectedAttacks.map((attack, index) => (
                    <tr key={index}>
                      <td style={{color: '#f87171', fontWeight: 'bold'}}>{attack.label}</td>
                      <td style={{fontFamily: 'monospace'}}>{attack.src}</td>
                      <td style={{fontFamily: 'monospace'}}>{attack.dst}</td>
                      <td>{attack.time}</td>
                      <td>
                        <span className="label-attack">%{Math.round(attack.confidence)}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

        </main>
      </div>
      
      {/* POP-UP UYARI */}
      {isUnderAttack && (
        <div className="popup-alert">
          <AlertTriangle size={32} />
          <div>
            <h4 style={{ margin: 0, fontSize: '1.1rem' }}>KRİTİK UYARI</h4>
            <p style={{ margin: '5px 0 0 0', fontSize: '0.9rem' }}>Ağda anormal aktivite tespit edildi!</p>
          </div>
          <button onClick={() => setIsUnderAttack(false)} className="popup-btn">
            KAPAT
          </button>
        </div>
      )}

    </div>
  );
};

// ==========================================
// 2. BİLEŞEN: APP (LOGIN VE GEÇİŞ MANTIĞI)
// ==========================================
const App = () => {
  // Durum Yönetimi
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [error, setError] = useState('');
  
  // Güvenlik / Kilitlenme
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [isLocked, setIsLocked] = useState(false);
  const [timeLeft, setTimeLeft] = useState(0);

  // Kilitlenme Süresi Yönetimi
  useEffect(() => {
    let timer;
    if (isLocked && timeLeft > 0) {
      timer = setInterval(() => {
        setTimeLeft((prev) => prev - 1);
      }, 1000);
    } else if (timeLeft === 0 && isLocked) {
      setIsLocked(false);
      setFailedAttempts(0);
      setError('');
    }
    return () => clearInterval(timer);
  }, [isLocked, timeLeft]);

  const handleLogin = (e) => {
    e.preventDefault();

    if (isLocked) return;

    // Şifre Kontrolü (Client Side)
    if (username === 'admin' && password === '1234') {
      setIsLoggedIn(true);
      setError('');
    } else {
      const newAttempts = failedAttempts + 1;
      setFailedAttempts(newAttempts);

      if (newAttempts >= 3) {
        setIsLocked(true);
        setTimeLeft(10);
        setError('Çok fazla başarısız deneme! Sistem kilitlendi.');
      } else {
        setError(`Hatalı giriş! Kalan hakkınız: ${3 - newAttempts}`);
      }
    }
  };

  // EĞER GİRİŞ YAPILDIYSA -> DASHBOARD'I GÖSTER
  if (isLoggedIn) {
    return <MainDashboard />;
  }

  // EĞER GİRİŞ YAPILMADIYSA -> LOGIN EKRANINI GÖSTER
  // Not: style={styles...} kısımları className olarak güncellendi (App.css'e uygun hale getirildi)
  return (
    <div className="login-container">
      <div className="login-box">
        <h2 className="login-title">Güvenlik Sistemi Girişi</h2>
        
        <form onSubmit={handleLogin}>
          <div className="input-group">
            <label className="input-label">Kullanıcı Adı</label>
            <input
              type="text"
              className="login-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={isLocked}
              placeholder="admin"
            />
          </div>

          <div className="input-group">
            <label className="input-label">Şifre</label>
            <input
              type="password"
              className="login-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={isLocked}
              placeholder="1234"
            />
          </div>

          {error && <p className="error-message">{error}</p>}
          
          {isLocked && (
            <p className="lock-message">
              Lütfen {timeLeft} saniye bekleyiniz...
            </p>
          )}

          <button 
            type="submit" 
            className="login-button"
            disabled={isLocked}
          >
            {isLocked ? 'KİLİTLİ' : 'GİRİŞ YAP'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default App;
