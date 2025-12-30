package nycu.winlab.proxyndp;

import org.onlab.packet.MacAddress;
import org.onlab.packet.IpAddress;

public class IpMac {
    private final IpAddress ip;
    private final MacAddress mac;
    private final MacAddress oldmac;

    public IpMac(IpAddress ip, MacAddress mac, MacAddress oldmac) {
        this.ip = ip;
        this.mac = mac;
        this.oldmac = oldmac;
    }

    public IpAddress getIp() {
        return ip;
    }

    public MacAddress getMac() {
        return mac;
    }

    public MacAddress getOldMac() {
        return oldmac;
    }
}


