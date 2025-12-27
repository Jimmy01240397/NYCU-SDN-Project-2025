package nycu.winlab.proxyndp;

import org.onlab.packet.MacAddress;
import org.onlab.packet.IpAddress;

public class IpMac {
    private final IpAddress ip;
    private final MacAddress mac;

    public IpMac(IpAddress ip, MacAddress mac) {
        this.ip = ip;
        this.mac = mac;
    }

    public IpAddress getIp() {
        return ip;
    }

    public MacAddress getMac() {
        return mac;
    }
}


