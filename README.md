"""
Repositório: Edge AI Security para Redes IoT Definidas por Software (SDN)
Artigo: Intelligent Edge AI-Based Security Architecture for Software-Defined IoT Networks (LANC 2026)
Autores: Helder Aood, Denis Rosário, Eduardo Cerqueira (UFPA)

Descrição: 
Este script implementa o motor de inferência na borda (Edge Node). 
Ele captura dados de fluxo, extrai características estatísticas, 
utiliza um modelo Random Forest pré-treinado para deteção de anomalias (DDoS/Port Scanning)
e interage proativamente com a API Sul do Controlador SDN para mitigação.
"""

import time
import numpy as np
import warnings
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# Suprimir avisos para manter o terminal limpo durante a execução
warnings.filterwarnings('ignore')

class EdgeSecurityNode:
    def __init__(self):
        print("[INIT] A inicializar o Nó de Segurança na Borda (Edge AI)...")
        # Inicializa o modelo (Na prática, isto seria carregado via joblib/pickle)
        # RF otimizado para baixa latência de inferência O(M * D)
        self.model = RandomForestClassifier(n_estimators=50, max_depth=15, random_state=42)
        self.scaler = StandardScaler()
        self._mock_train_model()
        print("[INIT] Modelo Random Forest e Scaler carregados com sucesso.")

    def _mock_train_model(self):
        """Simula o treino offline usando as 4 features principais do artigo:
        1. Bwd Pkt Len Std
        2. SYN Flag Count
        3. Pkt Length Mean
        4. Flow IAT Mean
        """
        # Dados de treino simulados (Benignos = 0, Anómalos = 1)
        X_train = np.array([
            [10.5, 0, 64.0, 150.0],  # Benigno
            [120.4, 8, 1200.0, 2.5], # DDoS SYN Flood
            [15.2, 0, 70.0, 140.0],  # Benigno
            [90.1, 5, 800.0, 5.0]    # Port Scan
        ])
        y_train = np.array([0, 1, 0, 1])
        
        self.scaler.fit(X_train)
        X_train_scaled = self.scaler.transform(X_train)
        self.model.fit(X_train_scaled, y_train)

    def extract_features(self, raw_flow_data):
        """
        Extrai as características estatísticas do fluxo.
        Na prática, isto processaria pacotes pcap ou registos sFlow/NetFlow.
        """
        # Simulação de extração em tempo real [Bwd Pkt Len Std, SYN Flag Count, Pkt Length Mean, Flow IAT Mean]
        features = np.array(raw_flow_data).reshape(1, -1)
        return self.scaler.transform(features)

    def block_flow_sdn_controller(self, ip_origem, porta):
        """
        Closed-Loop Mitigation: Injeta uma regra Drop no Switch OpenFlow via API do Controlador.
        """
        print(f"[MITIGAÇÃO] ⚠️ Ameaça confirmada! A enviar regra DROP para o Switch OpenFlow.")
        print(f"            Bloqueio efetuado para IP: {ip_origem} | Porta: {porta}")
        # Exemplo prático de payload para Ryu Controller:
        # requests.post('http://<RYU_IP>:8080/stats/flowentry/add', json=drop_rule_payload)
        pass

    def process_edge_flow(self, flow_metadata):
        """
        Pipeline principal de inferência de ML executado na Borda.
        """
        inicio = time.time()
        
        # 1. Extração de Features e Normalização
        features = self.extract_features(flow_metadata['data'])
        
        # 2. Inferência em Tempo Real
        predicao = self.model.predict(features)[0]
        
        latencia_ms = (time.time() - inicio) * 1000
        
        # 3. Mitigação Proativa (Closed-Loop)
        if predicao == 1: # 1 representa tráfego anómalo / ataque
            print(f"[ALERTA] Fluxo Malicioso Detetado! (Latência Deteção: {latencia_ms:.3f} ms)")
            self.block_flow_sdn_controller(flow_metadata['src_ip'], flow_metadata['src_port'])
        else:
            print(f"[INFO] Fluxo Benigno processado. (Latência: {latencia_ms:.3f} ms)")

        return predicao, latencia_ms

def simulate_network_traffic():
    """
    Função para simular a chegada contínua de tráfego IoT no gateway de borda.
    """
    edge_node = EdgeSecurityNode()
    
    print("\n[REDE] A iniciar monitorização de tráfego IoT no plano de dados...\n")
    
    # Simulação de fluxos de rede a chegar ao gateway
    fluxos_simulados = [
        {'src_ip': '192.168.1.15', 'src_port': 443,  'data': [11.2, 0, 68.5, 145.2]},  # Normal
        {'src_ip': '192.168.1.22', 'src_port': 80,   'data': [14.1, 0, 72.0, 138.9]},  # Normal
        {'src_ip': '10.0.0.55',    'src_port': 4444, 'data': [115.0, 9, 1100.0, 1.2]}, # Ataque (DDoS)
        {'src_ip': '192.168.1.10', 'src_port': 53,   'data': [10.8, 0, 65.0, 148.0]}   # Normal
    ]
    
    for fluxo in fluxos_simulados:
        time.sleep(0.5) # Simula o intervalo de chegada dos pacotes
        print(f"-> A analisar novo fluxo de {fluxo['src_ip']}:{fluxo['src_port']}...")
        edge_node.process_edge_flow(fluxo)

if __name__ == "__main__":
    simulate_network_traffic()
