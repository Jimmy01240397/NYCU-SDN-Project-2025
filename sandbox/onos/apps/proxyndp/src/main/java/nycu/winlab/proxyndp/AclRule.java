package nycu.winlab.proxyndp;

import com.fasterxml.jackson.databind.JsonNode;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.IpAddress;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import java.util.List;
import java.util.ArrayList;

public final class AclRule {

    public final DeviceId device;
    public final PortNumber port;
    public final IpPrefix sender;
    public final IpPrefix target;
    public final boolean request;
    public final String rule;
    public final String data;

    private AclRule(DeviceId device, PortNumber port, IpPrefix sender,
            IpPrefix target, boolean request, String rule, String data) {
        this.device = device;
        this.port = port;
        this.sender = sender;
        this.target = target;
        this.request = request;
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
            IpPrefix sender = n.has("sender")
                    ? IpPrefix.valueOf(n.get("sender").asText())
                    : null;
            IpPrefix target = n.has("target")
                    ? IpPrefix.valueOf(n.get("target").asText())
                    : null;

            boolean request =
                    "request".equalsIgnoreCase(n.get("type").asText());
            String rule = n.get("rule").asText();
            String data = n.has("data") ? n.get("data").asText() : "";

            rules.add(new AclRule(device, port, sender, target, request, rule, data));
        }
        return rules;
    }

    public boolean match(ConnectPoint point, IpAddress s, IpAddress t, boolean request) {
        if (device != null && !device.equals(point.deviceId())) {
            return false;
        }
        if (port != null && !port.equals(point.port())) {
            return false;
        }
        if (this.request != request) {
            return false;
        }
        if (sender != null && !sender.contains(s)) {
            return false;
        }
        if (target != null && !target.contains(t)) {
            return false;
        }
        return true;
    }
}
