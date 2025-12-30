package nycu.winlab.bridgeapp;

import nycu.winlab.proxyndp.ProxyNDP;

import com.fasterxml.jackson.databind.JsonNode;
import org.onosproject.net.flow.TrafficSelector;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.MacAddress;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import java.util.List;
import java.util.ArrayList;

public final class AclRule {

    public final DeviceId device;
    public final PortNumber port;
    public final IpAddress src;
    public final IpAddress dst;
    public final boolean strict;
    public final boolean linklocal;
    public final String rule;
    public final String data;
    public TrafficSelector selector;

    public AclRule(DeviceId device, PortNumber port, IpAddress src, IpAddress dst,
            boolean strict, boolean linklocal, String rule, String data) {
        this.device = device;
        this.port = port;
        this.src = src;
        this.dst = dst;
        this.strict = strict;
        this.linklocal = linklocal;
        this.rule = rule;
        this.data = data;
    }

    public static List<AclRule> parse(JsonNode array) {
        List<AclRule> rules = new ArrayList<>();
        if (array == null) {
            return rules;
        }

        for (JsonNode n : array) {
            DeviceId device = n.has("device")
                    ? DeviceId.deviceId(n.get("device").asText())
                    : null;
            PortNumber port = n.has("port")
                    ? PortNumber.portNumber(n.get("port").asInt())
                    : null;
            IpAddress src = n.has("src")
                    ? IpAddress.valueOf(n.get("src").asText())
                    : null;
            IpAddress dst = n.has("dst")
                    ? IpAddress.valueOf(n.get("dst").asText())
                    : null;

            boolean strict = n.has("strict") && n.get("strict").asBoolean();
            boolean linklocal = n.has("linklocal") && n.get("linklocal").asBoolean();
            String rule = n.get("rule").asText();
            String data = n.has("data") ? n.get("data").asText() : "";

            rules.add(new AclRule(device, port, src, dst, strict, linklocal, rule, data));
        }
        return rules;
    }

    public boolean match(ProxyNDP proxyndp, ConnectPoint point,
            IpAddress sip, IpAddress dip, MacAddress s, MacAddress d) {
        if (device != null && !device.equals(point.deviceId())) {
            return false;
        }
        if (port != null && !port.equals(point.port())) {
            return false;
        }
        ProxyNDP.CacheData srcmac = proxyndp.getdiscovercache(src);
        if (src != null && (srcmac == null || !srcmac.getMac().equals(s))) {
            return false;
        }
        ProxyNDP.CacheData dstmac = proxyndp.getdiscovercache(dst);
        if (dst != null && (dstmac == null || !dstmac.getMac().equals(d))) {
            return false;
        }
        if (strict) {
            if (linklocal) {
                IpPrefix linklocalprefix = IpPrefix.valueOf("fe80::/64");
                if (src != null &&
                   (sip == null || !linklocalprefix.contains(sip))) {
                    return false;
                }
                if (dst != null &&
                   (dip == null || !linklocalprefix.contains(dip))) {
                    return false;
                }
            } else {
                if (src != null && !src.equals(sip)) {
                    return false;
                }
                if (dst != null && !dst.equals(dip)) {
                    return false;
                }
            }
        }
        return true;
    }
}
