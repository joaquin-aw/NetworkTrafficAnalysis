import pandas as pd
import plotly.subplots as sp
import plotly.express as px
import requests
import time
from dotenv import load_dotenv
import os

load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_KEY")

def check_ip(ip, API_KEY):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        
        response = requests.get(url, headers=headers, params=params)
        data = response.json()["data"]
        
        return {
            "ip": ip,
            "abuse_score": data["abuseConfidenceScore"],
            "country": data["countryCode"],
            "total_reports": data["totalReports"],
            "last_reported": data["lastReportedAt"]
        }
    except Exception as e:
        print(f"Error checking {ip}: {e}")
        return None


df = pd.read_json("traffic_data.json")
df['timestamp'] = pd.to_datetime(df['timestamp'])

# local ip check
def is_local_ip(ip):
    if ip.startswith("192.168.") or ip.startswith("10."):
        return True
    parts = ip.split(".")
    if parts[0] == "172" and 16 <= int(parts[1]) <= 31:
        return True
    return False

# device count
all_local_ips = pd.concat([df["src_ip"], df["dst_ip"]])
unique_devices = all_local_ips[all_local_ips.apply(is_local_ip)].nunique()
total_packets = len(df)

# figures
fig1 = px.line(df, x='timestamp', y='size', title='Network Traffic Over Time')
#fig2 = px.bar(df, x='protocol', title='Protocol Distribution')
protocol_counts = df["protocol"].value_counts().reset_index()
protocol_counts.columns = ["protocol", "count"]
fig2 = px.bar(protocol_counts, x="protocol", y="count", title="Protocol Distribution")

#ports
port_labels = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    25: "SMTP",
    21: "FTP",
    67: "DHCP",
    123: "NTP",
    445: "SMB",
    5353: "mDNS",
    1900: "UPnP",
    5355: "LLMNR"
}

sus_ports = {
    #suspicious ports
    22: "SSH",
    23: "Telnet",
    1080: "SOCKS Proxy",
    3389: "RDP",
    4444: "Reverse Shell",
    6667: "IRC/Botnet",
}

df["port_label"] = df["dst_port"].map(port_labels).fillna("Other")
df["sus_port"] = df["dst_port"].map(sus_ports)
sus_traffic = df[df["sus_port"].notna()]

#fig3 = px.bar(df, x='port_label', title='Port Activity')
#fig3.update_layout(margin=dict(b=150))
port_counts = df["port_label"].value_counts().reset_index()
port_counts.columns = ["port_label", "count"]
fig3 = px.bar(port_counts, x="port_label", y="count", title="Port Activity")

# combine
fig = sp.make_subplots(rows=2, cols=2,
                       subplot_titles=('Network Traffic Over Time', 'Protocol Distribution', 'Port Activity', 'Known Suspicious Port Activity'))

fig.add_trace(fig1.data[0], row=1, col=1)
fig.add_trace(fig2.data[0], row=1, col=2)
fig.add_trace(fig3.data[0], row=2, col=1)

# get unique external IPs only
external_ips = df[~df["src_ip"].apply(is_local_ip)]["src_ip"].unique()

flagged = []

for ip in external_ips:
    result = check_ip(ip, API_KEY)
    if result["abuse_score"] > 0:
        flagged.append(result)
    time.sleep(0.5)  # avoid hitting rate limit

print(f"Checked {len(external_ips)} IPs")
print(f"Flagged {len(flagged)} malicious IPs")
for ip in flagged:
    print(f"{ip['ip']} - Score: {ip['abuse_score']} (0 - 100) - Reports: {ip['total_reports']}")


if not sus_traffic.empty:
    fig4 = px.bar(sus_traffic, x='sus_port', title='Known Suspicious Port Activity')
    fig.add_trace(fig4.data[0], row=2, col=2)
    #fig4.update_layout(margin=dict(b=150))
    #fig.update_xaxes(tickangle=45, row=2, col=2)

    fig.update_layout(
        height=800,
        width=1200,
        #title_text=f"Local Devices: {unique_devices} | Suspicious Port Activity Detected"
    )
    
else:
    fig.update_layout(
        height=800,
        width=1200,
        #title_text=f"Local Devices: {unique_devices} | No Suspicious Port Activity Detected"
    )


if flagged:
    flagged_df = pd.DataFrame(flagged)
    flagged_table = flagged_df.to_html(index=False, classes="table")
else:
    flagged_table = "<p style='color: green'> No malicious IPs detected</p>"

plot_html = fig.to_html(full_html=False)

html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Network Traffic Analysis</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: white; padding: 20px; }}
        h1 {{ color: #00d4ff; }}
        .stats {{ display: flex; gap: 20px; margin-bottom: 30px; }}
        .card {{ background: #16213e; padding: 20px; border-radius: 10px; flex: 1; text-align: center; }}
        .card h2 {{ font-size: 2em; margin: 0; color: #00d4ff; }}
        .card p {{ margin: 5px 0 0 0; color: #aaa; }}
        .table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        .table th, .table td {{ padding: 10px; border: 1px solid #444; text-align: left; }}
        .table th {{ background: #16213e; color: #00d4ff; }}
        .table tr:nth-child(even) {{ background: #16213e; }}
    </style>
</head>
<body>
    <h1>Network Traffic Analysis</h1>
    <div class="stats">
        <div class="card">
            <h2>{unique_devices}</h2>
            <p>Local Devices</p>
        </div>
        <div class="card">
            <h2>{total_packets}</h2>
            <p>Total Packets</p>
        </div>
        <div class="card">
            <h2>{len(sus_traffic)}</h2>
            <p>Suspicious Ports</p>
        </div>
        <div class="card">
            <h2>{len(flagged)}</h2>
            <p>Malicious IPs</p>
        </div>
    </div>
    {plot_html}
    <h2 style="color: #00d4ff; margin-top: 40px">Malicious IP Report</h2>
    {flagged_table}
</body>
</html>
"""

with open("network_traffic_analysis.html", "w") as f:
    f.write(html)