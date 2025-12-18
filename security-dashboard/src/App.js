import React, { useState, useEffect } from 'react';
import io from 'socket.io-client';
import './App.css';

const SecurityDashboard = () => {
  const [trafficData, setTrafficData] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [alertState, setAlertState] = useState({ active: false, data: null });

  useEffect(() => {
    const socket = io('http://localhost:5000');

    socket.on('new_packet', (data) => {
      // Listeye ekle (En son gelen en üstte)
      setTrafficData((prev) => [data, ...prev].slice(0, 15));

      // Saldırı ise Alarm Çal
      if (data.label !== 'NORMAL') {
        handleAnomaly(data);
      }
    });

    return () => socket.disconnect();
  }, []);

  const handleAnomaly = (packet) => {
    setAnomalies((prev) => [packet, ...prev]);
    setAlertState({ active: true, data: packet });
    setTimeout(() => {
      setAlertState({ active: false, data: null });
    }, 4000);
  };

  return (
    <div className={`app-container ${alertState.active ? 'alert-mode' : ''}`}>
      
      {/* HEADER */}
      <header className="main-header">
        <div>
            <h1>🛡️ AI NETWORK GUARD</h1>
            <small>Hybrid Architecture: Gatekeeper & Expert Models</small>
        </div>
        <div className={`status-badge ${alertState.active ? 'danger' : 'safe'}`}>
          {alertState.active ? `⚠️ TEHDİT: ${alertState.data?.label}` : '✅ SİSTEM GÜVENLİ'}
        </div>
      </header>

      <div className="dashboard-grid">
         {/* SOL PANEL: CANLI AKIŞ */}
         <div className="panel traffic-panel">
          <h2>📡 Canlı Paket Analizi</h2>
          <table>
            <thead>
              <tr>
                <th>Zaman</th>
                <th>Model Kaynağı</th>
                <th>Hedef Port</th>
                <th>Flow Bytes/s</th>
                <th>Karar</th>
              </tr>
            </thead>
            <tbody>
              {trafficData.map((data) => (
                <tr key={data.id} className={data.label !== 'NORMAL' ? 'row-danger' : 'row-safe'}>
                  <td>{data.timestamp}</td>
                  <td>
                    <span className={`badge ${data.source_model === 'Gatekeeper' ? 'badge-blue' : 'badge-purple'}`}>
                        {data.source_model}
                    </span>
                  </td>
                  <td>{data.destinationPort}</td>
                  <td>{Math.floor(data.flowBytesSec).toLocaleString()}</td>
                  <td style={{fontWeight: 'bold'}}>
                    {data.label} 
                    {data.label !== 'NORMAL' && <span className="conf-text"> (%{data.confidence.toFixed(1)})</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

         {/* SAĞ PANEL: SALDIRI GEÇMİŞİ */}
         <div className="panel anomaly-panel">
          <h2>💀 Tespit Edilen Tehditler</h2>
          {anomalies.length === 0 ? (
            <p className="no-data">Tehdit kaydı bulunamadı.</p>
          ) : (
            <ul className="log-list">
              {anomalies.map((anom, index) => (
                <li key={index} className="log-item">
                  <div className="log-header">
                    <span className="log-type">{anom.label}</span>
                    <span className="log-time">{anom.timestamp}</span>
                  </div>
                  <div className="log-details">
                    <span>Port: {anom.destinationPort}</span>
                    <span>Teyit: <strong>{anom.source_model}</strong></span>
                    <span>Güven: %{anom.confidence.toFixed(1)}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* POPUP ALERT */}
      {alertState.active && alertState.data && (
        <div className="popup-alert">
          <div className="alert-content">
            <h1>🚨 SALDIRI ENGELLENDİ</h1>
            <p className="alert-type">{alertState.data.label}</p>
            <div className="alert-meta">
                <span>Tespit Eden: {alertState.data.source_model}</span>
                <span>Güven Skoru: %{alertState.data.confidence.toFixed(2)}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecurityDashboard;