package nycu.winlab.bridgeapp;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.flow.FlowRuleService;
//import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.PortNumber;
import org.onosproject.net.DeviceId;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.Dictionary;
import java.util.Properties;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

//import static org.onlab.util.Tools.get;

@Component(immediate = true,
           service = {BridgeApp.class},
           property = {
           })
public class BridgeApp {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    private ApplicationId appId;

    private LearnPacketProcessor processor;

    private Map<DeviceId, Map<MacAddress, HostEntry>> mactables = new HashMap<>();

    private ReadWriteLock lock = new ReentrantReadWriteLock();

    @Activate
    protected void activate() {
        if (coreService == null || packetService == null) {
            return;
        }
        try {
            cfgService.registerProperties(getClass());
        } catch (IllegalArgumentException e) {

        }
        appId = coreService.registerApplication("nycu.winlab.bridgeapp");
        processor = new LearnPacketProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(2));
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    @Deactivate
    protected void deactivate() {
        if (coreService == null || packetService == null) {
            return;
        }
        try {
            cfgService.unregisterProperties(getClass(), false);
        } catch (IllegalArgumentException e) {

        }
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        processor = null;
        mactables.clear();
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        //if (context != null) {
        //}
    }

    private class LearnPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null) {
                return;
            }
            MacAddress srcmac = ethPkt.getSourceMAC();
            MacAddress dstmac = ethPkt.getDestinationMAC();
            if (ethPkt.getEtherType() == (short) 0x8942) {
                return;
            }
            if (!srcmac.isBroadcast() && !srcmac.isMulticast()) {
                newhostentry(context);
            }

            if (context.isHandled()) {
                return;
            }

            if (dstmac.isBroadcast() || dstmac.isMulticast()) {
                flood(context);
                return;
            }
            DeviceId deviceId = pkt.receivedFrom().deviceId();
            HostEntry dst = gethostentry(deviceId, dstmac);
            if (dst == null) {
                flood(context);
                return;
            }
            addrule(context, dst);
        }
    }

    private void flood(PacketContext context) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        MacAddress dstmac = ethPkt.getDestinationMAC();
        DeviceId deviceId = pkt.receivedFrom().deviceId();
        context.treatmentBuilder().setOutput(PortNumber.FLOOD);
        context.send();
        log.info("MAC address `{}` is missed on `{}`. Flood the packet.", dstmac, deviceId);
    }

    private void addrule(PacketContext context, HostEntry dst) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        MacAddress srcmac = ethPkt.getSourceMAC();
        PortNumber fromport = pkt.receivedFrom().port();
        DeviceId fromdevice = pkt.receivedFrom().deviceId();

        TrafficSelector selector = DefaultTrafficSelector.builder().
            matchEthSrc(dst.getMac()).
            matchEthDst(srcmac).
            build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().
            setOutput(fromport).
            build();
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder().
            withSelector(selector).
            withTreatment(treatment).
            withPriority(30).
            withFlag(ForwardingObjective.Flag.VERSATILE).
            fromApp(appId).
            makeTemporary(300).
            add();
        flowObjectiveService.forward(fromdevice, forwardingObjective);

        log.info("MAC address `{}` is matched on `{}/{}`. Install a flow rule.",
                srcmac, fromdevice, fromport);

        selector = DefaultTrafficSelector.builder().
            matchEthSrc(srcmac).
            matchEthDst(dst.getMac()).
            build();
        treatment = DefaultTrafficTreatment.builder().
            setOutput(dst.getPort()).
            build();
        forwardingObjective = DefaultForwardingObjective.builder().
            withSelector(selector).
            withTreatment(treatment).
            withPriority(30).
            withFlag(ForwardingObjective.Flag.VERSATILE).
            fromApp(appId).
            makeTemporary(300).
            add();
        flowObjectiveService.forward(dst.getDeviceId(), forwardingObjective);

        context.treatmentBuilder().setOutput(dst.getPort());
        context.send();
        log.info("MAC address `{}` is matched on `{}/{}`. Install a flow rule.",
                dst.getMac(), dst.getDeviceId(), dst.getPort());
    }

    private void newhostentry(PacketContext context) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        MacAddress srcmac = ethPkt.getSourceMAC();
        PortNumber fromport = pkt.receivedFrom().port();
        DeviceId deviceId = pkt.receivedFrom().deviceId();
        lock.writeLock().lock();
        try {
            Map<MacAddress, HostEntry> mactable = mactables.get(deviceId);
            if (mactable == null) {
                mactable = new HashMap<>();
                mactables.put(deviceId, mactable);
            }
            HostEntry entry = new HostEntry(deviceId, fromport, srcmac);
            if (!entry.equals(mactable.get(srcmac))) {
                mactable.put(srcmac, entry);
                log.info("Add an entry to the port table of `{}`. MAC address: `{}` => Port: `{}`.",
                        deviceId, srcmac, fromport);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    private HostEntry gethostentry(DeviceId deviceId, MacAddress mac) {
        lock.readLock().lock();
        try {
            Map<MacAddress, HostEntry> mactable = mactables.get(deviceId);
            if (mactable == null) {
                return null;
            }
            HostEntry result = mactable.get(mac);
            return result;
        } finally {
            lock.readLock().unlock();
        }
    }

    private class HostEntry {
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
    }
}
