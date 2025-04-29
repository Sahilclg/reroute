import json
import logging
import hashlib
import os
import requests
from nfstream import NFStreamer
from datetime import datetime

# Configure logging
logging.basicConfig(filename='flow_tracker.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# Output directory for JSON files
output_folder = "flow_data"
os.makedirs(output_folder, exist_ok=True)

# Generate timestamp for output files
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
flow_file = os.path.join(output_folder, f"flows_{timestamp}.json")
response_file = os.path.join(output_folder, f"api_responses_{timestamp}.json")

# API endpoint for local model
API_ENDPOINT = "http://localhost:8000/predict"

# EC2 endpoint to send alerts
EC2_ENDPOINT = "http://44.203.122.12:5000/ddos-alert"  # Replace with your EC2 IP

def generate_flow_id(flow):
    try:
        five_tuple = (
            flow.src_ip,
            flow.dst_ip,
            flow.src_port,
            flow.dst_port,
            flow.protocol
        )
        return hashlib.md5(str(five_tuple).encode()).hexdigest()[:8]
    except Exception as e:
        logging.error(f"Error generating FlowID: {e}")
        return None

def compile_flow_json(flow):
    try:
        flow_id = generate_flow_id(flow)
        if not flow_id:
            return None

        if flow.bidirectional_packets < 2:
            return None

        return {
            "FlowID": f"flow{flow_id}",
            "Flow_IAT_Mean": getattr(flow, 'bidirectional_mean_iat', 0.0) / 1000,
            "Idle_Mean": 0.0,
            "Fwd_IAT_Mean": getattr(flow, 'src2dst_mean_iat', 0.0) / 1000,
            "Packet_Length_Mean": getattr(flow, 'bidirectional_mean_piat', 0.0),
            "Fwd_Packet_Length_Mean": getattr(flow, 'src2dst_mean_piat', 0.0),
            "Flow_IAT_Std": getattr(flow, 'bidirectional_std_iat', 0.0) / 1000,
            "Fwd_Packet_Length_Min": getattr(flow, 'src2dst_min_piat', 0.0),
            "Idle_Min": 0.0,
            "Flow_IAT_Min": getattr(flow, 'bidirectional_min_iat', 0.0) / 1000,
            "Init_Fwd_Win_Bytes": getattr(flow, 'src2dst_init_windows_size', 0),
            "Packet_Length_Variance": getattr(flow, 'bidirectional_variance_piat', 0.0),
            "CWE_Flag_Count": getattr(flow, 'src2dst_cwr_packets', 0),
            "Protocol": flow.protocol,
            "Flow_Packets_per_s": flow.bidirectional_packets / (flow.bidirectional_duration_ms / 1000) if flow.bidirectional_duration_ms else 0.0,
            "Fwd_Packets_per_s": flow.src2dst_packets / (flow.bidirectional_duration_ms / 1000) if flow.bidirectional_duration_ms else 0.0,
            "Fwd_PSH_Flags": getattr(flow, 'src2dst_psh_packets', 0),
            "Fwd_Act_Data_Packets": getattr(flow, 'src2dst_data_packets', 0),
            "Fwd_IAT_Std": getattr(flow, 'src2dst_std_iat', 0.0) / 1000,
            "Avg_Fwd_Segment_Size": getattr(flow, 'src2dst_mean_piat', 0.0),
            "Flow_IAT_Max": getattr(flow, 'bidirectional_max_iat', 0.0) / 1000,
            "Total_Fwd_Packets": flow.src2dst_packets,
            "Subflow_Fwd_Packets": flow.src2dst_packets / flow.bidirectional_packets if flow.bidirectional_packets else 0.0,
            "Fwd_IAT_Min": getattr(flow, 'src2dst_min_iat', 0.0) / 1000,
            "URG_Flag_Count": getattr(flow, 'src2dst_urg_packets', 0),
            "ACK_Flag_Count": getattr(flow, 'src2dst_ack_packets', 0),
            "RST_Flag_Count": getattr(flow, 'src2dst_rst_packets', 0),
            "Fwd_Packet_Length_Std": getattr(flow, 'src2dst_std_piat', 0.0),
            "Fwd_IAT_Max": getattr(flow, 'src2dst_max_iat', 0.0) / 1000,
            "Packet_Length_Min": getattr(flow, 'bidirectional_min_piat', 0.0),
            "Active_Max": flow.bidirectional_duration_ms / 1000
        }
    except Exception as e:
        logging.error(f"Error compiling flow JSON: {e}")
        return None

def call_api(flow_json, flow):
    try:
        response = requests.post(API_ENDPOINT, json=flow_json, timeout=15)
        response.raise_for_status()
        api_response = response.json()

        if not all(k in api_response for k in ["FlowID", "Prediction"]):
            return None

        source_ip = flow.src_ip
        avg_packet_size = flow.bidirectional_bytes / flow.bidirectional_packets if flow.bidirectional_packets > 0 else 0.0

        return {
            "FlowID": api_response["FlowID"],
            "Prediction": api_response["Prediction"],
            "source_ip": source_ip,
            "avg_packet_size": avg_packet_size
        }
    except Exception as e:
        logging.error(f"API error: {e}")
        return None

def send_to_ec2(data):
    try:
        response = requests.post(EC2_ENDPOINT, json=data, timeout=10)
        response.raise_for_status()
        print(f"Sent to EC2: {response.status_code}")
    except Exception as e:
        logging.error(f"EC2 send error: {e}")
        print(f"Error sending to EC2: {e}")

def main():
    try:
        streamer = NFStreamer(
            source="enp0s3",  # Replace with your network interface or a .pcap file
            statistical_analysis=True,
            idle_timeout=15,
            active_timeout=120,
            splt_analysis=10,
            bpf_filter="tcp or udp"
        )

        with open(flow_file, "a") as flow_f, open(response_file, "a") as resp_f:
            for flow in streamer:
                try:
                    flow_json = compile_flow_json(flow)
                    if not flow_json:
                        continue

                    flow_f.write(json.dumps(flow_json) + "\n")
                    flow_f.flush()
                    print(f"Flow JSON:\n{json.dumps(flow_json, indent=2)}")

                    api_response = call_api(flow_json, flow)
                    if api_response:
                        resp_f.write(json.dumps(api_response) + "\n")
                        resp_f.flush()
                        print(f"API Response:\n{json.dumps(api_response, indent=2)}")

                        send_to_ec2(api_response)
                    else:
                        print(f"No valid API response for {flow_json['FlowID']}")
                except Exception as e:
                    logging.error(f"Processing error: {e}")
                    print(f"Processing error: {e}")
                    continue
    except Exception as e:
        logging.error(f"Streamer error: {e}")
        print(f"Streamer error: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped by user")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        print(f"Fatal error: {e}")

