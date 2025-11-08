import dpkt  # parse captured network data
import socket  # functions to work with IP addresses
import geoip2.database  # translate IP addresses to geographical locations
import ipaddress

#Load GeoLite2 database
gi = geoip2.database.Reader(r'D:\GeoLite2-City.mmdb')
try:
    my_ip = socket.gethostbyname(socket.gethostname())
except Exception:
    my_ip = "192.168.18.84"  # fallback
print(f"my ip is:{my_ip}")
#Store missing IPs globally to report at end
missing_ips = []
def get_geo(ip):
    try:
        return gi.city(ip)
    except Exception:
        return None

def fake_local_location():
    return (17.3850, 78.4867) #fallback: hyderabad

def retKML(srcip, dstip):
    try:
        src = get_geo(srcip)
        dst = get_geo(dstip)
        
        #determine coordinates and/or give fake incase of missing ips
        if src and src.location:
            srclat, srclong = src.location.latitude, src.location.longitude
        elif ipaddress.ip_address(srcip).is_private:
            srclat, srclong = fake_local_location()
        else:
            missing_ips.append(srcip)
            srclat, srclong = fake_local_location()

        if dst and dst.location:
            dstlat, dstlong = dst.location.latitude, dst.location.longitude
        elif ipaddress.ip_address(dstip).is_private:
            dstlat, dstlong = fake_local_location()
        else:
            missing_ips.append(dstip)
            dstlat, dstlong = fake_local_location()

        #determine direction
        if srcip == my_ip:
            direction = "Outgoing"
            label = f"Outgoing packet to {dstip}"
        elif dstip == my_ip:
            direction = "Incoming"
            label = f"Incoming packet from {srcip}"
        else:
            direction = "Other"
            label = f"Transit packet from {srcip} to {dstip}"
        

        kml = f"""
        <Placemark>
            <name>{label}</name>
            <description><![CDATA[
                <b>Direction:</b> {direction}<br/>
                <b>Source IP:</b> {srcip}<br/>
                <b>Destination IP:</b> {dstip}<br/>
                <b>Source Location:</b> {src.city.name if src and src.city else "Unknown"}, {src.country.name if src and src.country else "Unknown"}<br/>
                <b>Destination Location:</b> {dst.city.name if dst and dst.city else "Unknown"}, {dst.country.name if dst and dst.country else "Unknown"}
            ]]></description>
            <styleUrl>#redLine</styleUrl>
            <LineString>
                <tessellate>1</tessellate>
                <coordinates>{srclong},{srclat},0 {dstlong},{dstlat},0</coordinates>
            </LineString>
        </Placemark>
        """
        return kml
    except Exception:
        return ''


def plotIPs(pcap):
    kmlPts = ''
    count = 0
    batch=[]
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            srcip = socket.inet_ntoa(ip.src)
            dstip = socket.inet_ntoa(ip.dst)

            #print(srcip, "->", dstip)
            if ipaddress.ip_address(srcip).is_private and ipaddress.ip_address(dstip).is_private:
                continue  # skip local/private IPs

            kmlPts += retKML(srcip, dstip)
            count += 1
            batch.append(dstip)

            #Print all valid packets (every 10 packets to improve speed)
            if len(batch) >= 10:
                print(f"Packets {count-9} to {count}: {', '.join(batch)}\n")
                batch.clear()
            
        except Exception:
            continue
    if batch:
        print(f"Packets {count-len(batch)+1} to {count}: {', '.join(batch)}\n")
        batch.clear()

    print("Total IPv4 packets processed:", count)
    print("Length of KML data generated:", len(kmlPts))
    return kmlPts


def main():
    with open('capture.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        kmlheader = """<?xml version="1.0" encoding="UTF-8"?>
        <kml xmlns="http://www.opengis.net/kml/2.2">
        <Document>
        <Style id="redLine">
            <LineStyle>
                <color>ff0000ff</color>
                <width>4</width>
            </LineStyle>
        </Style>"""

        test_line = """
        <Placemark>
            <name>Test Line</name>
            <styleUrl>#transPolyBlue</styleUrl>
            <LineString>
                <coordinates>77.5946,12.9716,0 72.8777,19.0760,0</coordinates>
            </LineString>
        </Placemark>
        """

        kmlfooter = """</Document></kml>"""

        kmldoc = kmlheader + test_line + plotIPs(pcap) + kmlfooter

    with open('network_traffic.kml', 'w', encoding='utf-8') as output:
        output.write(kmldoc)

    #Summary report of skipped IPs
    if missing_ips:
        print(f"{len(missing_ips)} IPs not found in GeoLite database.")
    print("Test Line from Mumbai to Bangalore included.")
    print("KML file created: network_traffic.kml")

if __name__ == '__main__':
    main()
