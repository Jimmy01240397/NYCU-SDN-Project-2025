package nycu.winlab.bridgeapp;

import com.fasterxml.jackson.databind.JsonNode;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onlab.packet.MacAddress;
import java.util.Objects;
import java.util.List;
import java.util.ArrayList;

public class HostEntry {
    private MacAddress mac;
    private DeviceId deviceId;
    private PortNumber port;
    public HostEntry(DeviceId deviceId, PortNumber port, MacAddress mac) {
        this.mac = mac;
        this.port = port;
        this.deviceId = deviceId;
    }
    public MacAddress getMac() {
        return mac;
    }
    public DeviceId getDeviceId() {
        return deviceId;
    }
    public PortNumber getPort() {
        return port;
    }
    @Override
    public int hashCode() {
        return Objects.hash(mac, deviceId, port);
    }
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        HostEntry entry = (HostEntry) o;
        return mac.equals(entry.mac) &&
            deviceId.equals(entry.deviceId) &&
            port.equals(entry.port);
    }
    public static List<HostEntry> parse(JsonNode array) {
        List<HostEntry> hostentrys = new ArrayList<>();
        if (array == null) {
            return hostentrys;
        }
        for (JsonNode n : array) {
            DeviceId device = n.has("device")
                    ? DeviceId.deviceId(n.get("device").asText())
                    : null;
            PortNumber port = PortNumber.portNumber(n.get("port").asInt());
            MacAddress mac = MacAddress.valueOf(n.get("mac").asText());
            hostentrys.add(new HostEntry(device, port, mac));
        }
        return hostentrys;
    }
}
