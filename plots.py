import pandas as pd
import plotly.subplots as sp
import plotly.express as px

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
fig2 = px.histogram(df, x='protocol', title='Protocol Distribution')

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

fig3 = px.bar(df, x='port_label', title='Port Activity')
#fig3.update_layout(margin=dict(b=150))

# combine
fig = sp.make_subplots(rows=2, cols=2,
                       subplot_titles=('Network Traffic Over Time', 'Protocol Distribution', 'Port Activity', 'Known Suspicious Port Activity'))

fig.add_trace(fig1.data[0], row=1, col=1)
fig.add_trace(fig2.data[0], row=1, col=2)
fig.add_trace(fig3.data[0], row=2, col=1)


if not sus_traffic.empty:
    fig4 = px.bar(sus_traffic, x='sus_port', title='Known Suspicious Port Activity')
    fig.add_trace(fig4.data[0], row=2, col=2)
    #fig4.update_layout(margin=dict(b=150))
    #fig.update_xaxes(tickangle=45, row=2, col=2)

    fig.update_layout(
        height=1200,
        width=1200,
        title_text=f"Network Traffic Analysis | Local Devices: {unique_devices} | Total Packets: {total_packets} | Suspicious Port Activity Detected"
    )
    
else:
    fig.update_layout(
        height=1200,
        width=1200,
        title_text=f"Network Traffic Analysis | Local Devices: {unique_devices} | Total Packets: {total_packets} | No Suspicious Port Activity Detected"
    )

fig.write_html("network_traffic_analysis.html")
print("Saved to network_traffic_analysis.html")