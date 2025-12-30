package nycu.winlab.routerapp;

import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;

@SuppressWarnings("checkstyle:AbbreviationAsWordInName")
public class IpInfo {
    private final IpPrefix prefix;
    private final IpAddress address;

    public IpInfo(IpAddress address, IpPrefix prefix) {
        this.address = address;
        this.prefix = prefix;
    }

    public IpAddress getAddress() {
        return address;
    }

    public IpPrefix getPrefix() {
        return prefix;
    }
}



