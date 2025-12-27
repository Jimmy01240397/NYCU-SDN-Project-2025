package nycu.winlab.bridgeapp;

import nycu.winlab.proxyndp.ProxyNDP;
import nycu.winlab.proxyndp.MacEventListener;
import nycu.winlab.proxyndp.MacEvent;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceEvent;
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
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.PortNumber;
import org.onosproject.net.Port;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Device;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.Dictionary;
import java.util.Properties;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

//import static org.onlab.util.Tools.get;

@Component(immediate = true,
           service = {BridgeApp.class},
           property = {
           })
public class BridgeApp {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final BridgeAppACLConfigListener cfgListener = new BridgeAppACLConfigListener();

    private final ConfigFactory<ApplicationId, BridgeAppACLConfig> factory =
        new ConfigFactory<ApplicationId, BridgeAppACLConfig>(
            APP_SUBJECT_FACTORY, BridgeAppACLConfig.class, "BridgeAppACLConfig") {
        @Override
        public BridgeAppACLConfig createConfig() {
            return new BridgeAppACLConfig();
        }
    };

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ProxyNDP proxyndp;

    private ApplicationId appId;

    private final BridgeAppMacEventListener maceventlistener = new BridgeAppMacEventListener();

    private final DeviceListener devicelistener = new BridgeAppDeviceListener();

    private LearnPacketProcessor processor;

    private Map<DeviceId, Map<MacAddress, HostEntry>> mactables = new HashMap<>();

    private ReadWriteLock lock = new ReentrantReadWriteLock();

    private List<AclRule> inputRules = new ArrayList<>();
    private List<AclRule> outputRules = new ArrayList<>();

    @Activate
    protected void activate() {
        if (coreService == null || packetService == null || cfgService == null) {
            return;
        }
        appId = coreService.registerApplication("nycu.winlab.bridgeapp");
        cfgService.addListener(cfgListener);
        cfgService.registerConfigFactory(factory);
        processor = new LearnPacketProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(2));
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        proxyndp.addListener(maceventlistener);
        deviceService.addListener(devicelistener);
    }

    @Deactivate
    protected void deactivate() {
        if (coreService == null || packetService == null) {
            return;
        }
        cfgService.removeListener(cfgListener);
        cfgService.unregisterConfigFactory(factory);
        proxyndp.removeListener(maceventlistener);
        deviceService.removeListener(devicelistener);
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        processor = null;
        mactables.clear();
    }

    private boolean aclcheck(Ethernet ethPkt, ConnectPoint point, String table) {
        List<AclRule> rules = null;
        switch (table) {
            case "input":
                rules = inputRules;
                break;
            case "output":
                rules = outputRules;
                break;
            default:
                return true;
        }
        for (AclRule rule : rules) {
            if (rule.match(proxyndp, point,
                           ethPkt.getSourceMAC(),
                           ethPkt.getDestinationMAC())) {
                switch (rule.rule) {
                    case "accept":
                        return true;
                    case "deny":
                        return false;
                    default:
                        break;
                }
            }
        }
        return true;
    }

    private boolean acltoflow(AclRule rule, int priority) {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        if (rule.port != null) {
            selector.matchInPort(rule.port);
        }
        if (rule.src != null) {
            ProxyNDP.CacheData srcmac = proxyndp.getdiscovercache(rule.src);
            if (srcmac == null) {
                return false;
            }
            selector.matchEthSrc(srcmac.getMac());
        }
        if (rule.dst != null) {
            ProxyNDP.CacheData dstmac = proxyndp.getdiscovercache(rule.dst);
            if (dstmac == null) {
                return false;
            }
            selector.matchEthDst(dstmac.getMac());
        }
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
        switch (rule.rule) {
            case "accept":
                treatment.setOutput(PortNumber.CONTROLLER);
                break;
            case "deny":
                treatment.drop();
                break;
            default:
                return false;
        }
        rule.selector = selector.build();
        TrafficTreatment treatmentbuilded = treatment.build();
        for (Device device : deviceService.getDevices()) {
            if (rule.device == null || device.id().equals(rule.device)) {
                ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder().
                    withSelector(rule.selector).
                    withTreatment(treatmentbuilded).
                    withPriority(priority).
                    withFlag(ForwardingObjective.Flag.VERSATILE).
                    fromApp(appId).
                    makePermanent().
                    add();
                flowObjectiveService.forward(device.id(), forwardingObjective);
            }
        }
        return true;
    }

    private boolean removeaclflow(AclRule rule, int priority) {
        if (rule.selector == null) {
            return false;
        }
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
        switch (rule.rule) {
            case "accept":
                treatment.setOutput(PortNumber.CONTROLLER);
                break;
            case "deny":
                treatment.drop();
                break;
            default:
                return false;
        }
        TrafficTreatment treatmentbuilded = treatment.build();
        for (Device device : deviceService.getDevices()) {
            if (rule.device == null || device.id().equals(rule.device)) {
                ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder().
                    withSelector(rule.selector).
                    withTreatment(treatmentbuilded).
                    withPriority(priority).
                    withFlag(ForwardingObjective.Flag.VERSATILE).
                    fromApp(appId).
                    remove();
                flowObjectiveService.forward(device.id(), forwardingObjective);
            }
        }
        return true;
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
            DeviceId deviceId = pkt.receivedFrom().deviceId();
            PortNumber fromport = pkt.receivedFrom().port();
            ConnectPoint frompoint = new ConnectPoint(deviceId, fromport);
            if (!aclcheck(ethPkt, frompoint, "input")) {
                return;
            }
            if (dstmac.isBroadcast() || dstmac.isMulticast()) {
                flood(context);
                return;
            }
            HostEntry dst = gethostentry(deviceId, dstmac);
            if (dst == null) {
                flood(context);
                return;
            }
            addrule(context, dst);
        }
    }

    @SuppressWarnings("checkstyle:AbbreviationAsWordInName")
    private class BridgeAppACLConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
                    && event.configClass().equals(BridgeAppACLConfig.class)) {
                BridgeAppACLConfig config = cfgService.getConfig(appId, BridgeAppACLConfig.class);
                if (config != null) {
                    for (int i = 0; inputRules != null && i < inputRules.size(); i++) {
                        AclRule rule = inputRules.get(i);
                        removeaclflow(rule, 1000 - i);
                    }
                    inputRules = config.getInputRules();
                    outputRules = config.getOutputRules();
                    for (int i = 0; i < inputRules.size(); i++) {
                        AclRule rule = inputRules.get(i);
                        acltoflow(rule, 1000 - i);
                    }
                }
            }
        }
    }

    private class BridgeAppMacEventListener implements MacEventListener {
        @Override
        public void event(MacEvent macevent) {
            for (int i = 0; inputRules != null && i < inputRules.size(); i++) {
                AclRule rule = inputRules.get(i);
                if ((rule.src != null && rule.src.equals(macevent.subject().getIp())) ||
                    (rule.dst != null && rule.dst.equals(macevent.subject().getIp()))) {
                    removeaclflow(rule, 1000 - i);
                    acltoflow(rule, 1000 - i);
                }
            }
        }
    }

    private class BridgeAppDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            Device device = event.subject();
            switch (event.type()) {
                case DEVICE_ADDED:
                    for (int i = 0; inputRules != null && i < inputRules.size(); i++) {
                        AclRule rule = inputRules.get(i);
                        if (rule.device.equals(device.id())) {
                            removeaclflow(rule, 1000 - i);
                            acltoflow(rule, 1000 - i);
                        }
                    }
                    break;
                default:
                    break;
            }
        }
    }

    private void flood(PacketContext context) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        MacAddress dstmac = ethPkt.getDestinationMAC();
        DeviceId deviceId = pkt.receivedFrom().deviceId();
        PortNumber fromport = pkt.receivedFrom().port();
        ConnectPoint frompoint = new ConnectPoint(deviceId, fromport);
        TrafficTreatment.Builder treatment = context.treatmentBuilder();

        for (Port port : deviceService.getPorts(deviceId)) {
            ConnectPoint outpoint = new ConnectPoint(deviceId, port.number());
            if (port.number().equals(PortNumber.LOCAL) ||
                outpoint.equals(frompoint)) {
                continue;
            }
            if (!aclcheck(ethPkt, outpoint, "output")) {
                continue;
            }
            treatment.setOutput(port.number());
        }

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
            matchInPort(dst.getPort()).
            matchEthSrc(dst.getMac()).
            matchEthDst(srcmac).
            build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().
            setOutput(fromport).
            build();
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder().
            withSelector(selector).
            withTreatment(treatment).
            withPriority(2000).
            withFlag(ForwardingObjective.Flag.VERSATILE).
            fromApp(appId).
            makeTemporary(300).
            add();
        flowObjectiveService.forward(fromdevice, forwardingObjective);

        log.info("MAC address `{}` is matched on `{}/{}`. Install a flow rule.",
                srcmac, fromdevice, fromport);

        selector = DefaultTrafficSelector.builder().
            matchInPort(fromport).
            matchEthSrc(srcmac).
            matchEthDst(dst.getMac()).
            build();
        treatment = DefaultTrafficTreatment.builder().
            setOutput(dst.getPort()).
            build();
        forwardingObjective = DefaultForwardingObjective.builder().
            withSelector(selector).
            withTreatment(treatment).
            withPriority(2000).
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
