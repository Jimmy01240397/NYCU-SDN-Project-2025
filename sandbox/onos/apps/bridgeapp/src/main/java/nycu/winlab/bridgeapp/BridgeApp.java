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
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
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
import org.onosproject.net.link.LinkService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.PortNumber;
import org.onosproject.net.Port;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Device;
import org.onosproject.net.Link;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.IpAddress;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.IpPrefix;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Properties;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.nio.ByteBuffer;

//import static org.onlab.util.Tools.get;

@Component(immediate = true,
           service = {BridgeApp.class},
           property = {
           })
public class BridgeApp {
    private static final int BRIDGERULEPRIORITY = 3000;
    private static final int ACLRULEPRIORITY = 1000;

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final BridgeAppConfigListener cfgListener = new BridgeAppConfigListener();

    private final ConfigFactory<ApplicationId, BridgeAppACLConfig> aclfactory =
        new ConfigFactory<ApplicationId, BridgeAppACLConfig>(
            APP_SUBJECT_FACTORY, BridgeAppACLConfig.class, "BridgeAppACLConfig") {
        @Override
        public BridgeAppACLConfig createConfig() {
            return new BridgeAppACLConfig();
        }
    };

    private final ConfigFactory<ApplicationId, BridgeAppInitConfig> initfactory =
        new ConfigFactory<ApplicationId, BridgeAppInitConfig>(
            APP_SUBJECT_FACTORY, BridgeAppInitConfig.class, "BridgeAppInitConfig") {
        @Override
        public BridgeAppInitConfig createConfig() {
            return new BridgeAppInitConfig();
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
    protected LinkService linkService;

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
        cfgService.registerConfigFactory(aclfactory);
        cfgService.registerConfigFactory(initfactory);
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
        cfgService.unregisterConfigFactory(aclfactory);
        cfgService.unregisterConfigFactory(initfactory);
        proxyndp.removeListener(maceventlistener);
        deviceService.removeListener(devicelistener);
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        processor = null;
        mactables.clear();
    }

    public AclRule aclcheck(Ethernet ethPkt, ConnectPoint point, String table) {
        List<AclRule> rules = null;
        switch (table) {
            case "input":
                rules = inputRules;
                break;
            case "output":
                rules = outputRules;
                break;
            default:
                return new AclRule(null, null, null, null, false, false, "accept", "");
        }
        for (AclRule rule : rules) {
            IpAddress sip = null;
            IpAddress dip = null;
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
                sip = Ip4Address.valueOf(ipv4Pkt.getSourceAddress());
                dip = Ip4Address.valueOf(ipv4Pkt.getDestinationAddress());
            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6Pkt = (IPv6) ethPkt.getPayload();
                sip = Ip6Address.valueOf(ipv6Pkt.getSourceAddress());
                dip = Ip6Address.valueOf(ipv6Pkt.getDestinationAddress());
            }
            //log.info("Test acl {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
            //        table, rule.rule, point,
            //        ethPkt.getSourceMAC(),
            //        ethPkt.getDestinationMAC(),
            //        sip, dip,
            //        rule.device,
            //        rule.port,
            //        rule.src,
            //        rule.dst,
            //        rule.strict,
            //        rule.linklocal,
            //        rule.src == null ? null : rule.src.equals(sip),
            //        rule.dst == null ? null : rule.dst.equals(dip),
            //        rule.match(proxyndp, point, sip, dip,
            //                   ethPkt.getSourceMAC(),
            //                   ethPkt.getDestinationMAC())
            //        );
            if (rule.match(proxyndp, point, sip, dip,
                           ethPkt.getSourceMAC(),
                           ethPkt.getDestinationMAC())) {
                switch (rule.rule) {
                    case "log":
                        log.info("ACL log table: {} point: {} source ip: {} source mac: {} dst ip: {} dst mac: {}",
                                table, point, sip, ethPkt.getSourceMAC(),
                                dip, ethPkt.getDestinationMAC());
                        break;
                    case "accept":
                        return rule;
                    case "deny":
                        return rule;
                    default:
                        break;
                }
            }
        }
        return new AclRule(null, null, null, null, false, false, "accept", "");
    }

    private boolean acltoflow(AclRule rule, int priority) {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        if (rule.strict) {
            boolean ip6 = (rule.src != null && rule.src.isIp6()) ||
                          (rule.dst != null && rule.dst.isIp6());
            if (!ip6) {
                selector.matchEthType(Ethernet.TYPE_IPV4);
                if (rule.src != null) {
                    selector.matchIPSrc(IpPrefix.valueOf(rule.src, 32));
                }
                if (rule.dst != null) {
                    selector.matchIPDst(IpPrefix.valueOf(rule.dst, 32));
                }
            } else {
                selector.matchEthType(Ethernet.TYPE_IPV6);
                if (rule.linklocal) {
                    IpPrefix linklocalprefix = IpPrefix.valueOf("fe80::/64");
                    if (rule.src != null) {
                        selector.matchIPv6Src(linklocalprefix);
                    }
                    if (rule.dst != null) {
                        selector.matchIPv6Dst(linklocalprefix);
                    }
                } else {
                    if (rule.src != null) {
                        selector.matchIPv6Src(IpPrefix.valueOf(rule.src, 128));
                    }
                    if (rule.dst != null) {
                        selector.matchIPv6Dst(IpPrefix.valueOf(rule.dst, 128));
                    }
                }
            }
        }
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
            if (aclcheck(ethPkt, frompoint, "input").rule.equalsIgnoreCase("deny")) {
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
    private class BridgeAppConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            if (event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED) {
                if (event.configClass().equals(BridgeAppACLConfig.class)) {
                    BridgeAppACLConfig config = cfgService.getConfig(appId, BridgeAppACLConfig.class);
                    if (config != null) {
                        for (int i = 0; inputRules != null && i < inputRules.size(); i++) {
                            AclRule rule = inputRules.get(i);
                            removeaclflow(rule, ACLRULEPRIORITY - i);
                        }
                        inputRules = config.getInputRules();
                        outputRules = config.getOutputRules();
                        for (int i = 0; i < inputRules.size(); i++) {
                            AclRule rule = inputRules.get(i);
                            acltoflow(rule, ACLRULEPRIORITY - i);
                        }
                    }
                }

                if (event.configClass().equals(BridgeAppInitConfig.class)) {
                    BridgeAppInitConfig config = cfgService.getConfig(appId, BridgeAppInitConfig.class);
                    if (config != null) {
                        List<HostEntry> hostentrys = config.getHostEntry();
                        for (int i = 0; i < hostentrys.size(); i++) {
                            HostEntry hostentry = hostentrys.get(i);
                            if (hostentry.getDeviceId() != null) {
                                DeviceId deviceId = hostentry.getDeviceId();
                                newhostentry(hostentry.getMac(), deviceId, hostentry.getPort());
                                continue;
                            }
                            for (Device device : deviceService.getDevices()) {
                                DeviceId deviceId = device.id();
                                newhostentry(hostentry.getMac(), deviceId, hostentry.getPort());
                            }
                        }
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
                    removeaclflow(rule, ACLRULEPRIORITY - i);
                    acltoflow(rule, ACLRULEPRIORITY - i);
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
                        if (rule.device == null || rule.device.equals(device.id())) {
                            removeaclflow(rule, ACLRULEPRIORITY - i);
                            acltoflow(rule, ACLRULEPRIORITY - i);
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
        TrafficTreatment.Builder contexttreatment = context.treatmentBuilder();
        flood(context, contexttreatment, ethPkt);
    }

    public void flood(PacketContext context, TrafficTreatment.Builder treatment,
            Ethernet ethPkt) {
        InboundPacket pkt = context.inPacket();
        MacAddress dstmac = ethPkt.getDestinationMAC();
        DeviceId deviceId = pkt.receivedFrom().deviceId();
        PortNumber fromport = pkt.receivedFrom().port();
        ConnectPoint frompoint = new ConnectPoint(deviceId, fromport);

        for (Port port : deviceService.getPorts(deviceId)) {
            ConnectPoint outpoint = new ConnectPoint(deviceId, port.number());
            if (port.number().equals(PortNumber.LOCAL) ||
                outpoint.equals(frompoint)) {
                continue;
            }
            if (aclcheck(ethPkt, outpoint, "output").rule.equalsIgnoreCase("deny")) {
                continue;
            }
            treatment.setOutput(port.number());
        }
        byte[] data = ethPkt.serialize();
        OutboundPacket outPkt = new DefaultOutboundPacket(
                deviceId,
                treatment.build(),
                ByteBuffer.wrap(data)
        );
        packetService.emit(outPkt);
        context.block();

        //context.send();
        log.info("MAC address `{}` is missed on `{}`. Flood the packet.", dstmac, deviceId);
    }

    private void addrule(PacketContext context, HostEntry dst) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        MacAddress srcmac = ethPkt.getSourceMAC();
        PortNumber fromport = pkt.receivedFrom().port();
        DeviceId fromdevice = pkt.receivedFrom().deviceId();

        AclRule rule = aclcheck(ethPkt, new ConnectPoint(dst.getDeviceId(), dst.getPort()),
                "output");

        if (rule.rule.equalsIgnoreCase("deny")) {
            return;
        }

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();

        if (rule.strict) {
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                selector.matchEthType(Ethernet.TYPE_IPV4);
                if (rule.src != null) {
                    selector.matchIPSrc(IpPrefix.valueOf(rule.src, 32));
                }
                if (rule.dst != null) {
                    selector.matchIPDst(IpPrefix.valueOf(rule.dst, 32));
                }
            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                selector.matchEthType(Ethernet.TYPE_IPV6);
                if (rule.linklocal) {
                    IpPrefix linklocalprefix = IpPrefix.valueOf("fe80::/64");
                    if (rule.src != null) {
                        selector.matchIPv6Src(linklocalprefix);
                    }
                    if (rule.dst != null) {
                        selector.matchIPv6Dst(linklocalprefix);
                    }
                } else {
                    if (rule.src != null) {
                        selector.matchIPv6Src(IpPrefix.valueOf(rule.src, 128));
                    }
                    if (rule.dst != null) {
                        selector.matchIPv6Dst(IpPrefix.valueOf(rule.dst, 128));
                    }
                }
            } else {
                return;
            }
        }

        selector.matchEthSrc(srcmac);
        selector.matchEthDst(dst.getMac());
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().
            setOutput(dst.getPort()).
            build();
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder().
            withSelector(selector.build()).
            withTreatment(treatment).
            withPriority(BRIDGERULEPRIORITY).
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

    public void newhostentry(PacketContext context) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        MacAddress srcmac = ethPkt.getSourceMAC();
        PortNumber fromport = pkt.receivedFrom().port();
        DeviceId deviceId = pkt.receivedFrom().deviceId();
        boolean run = (ethPkt.getEtherType() != Ethernet.TYPE_IPV4 &&
                       ethPkt.getEtherType() != Ethernet.TYPE_IPV6);
        if (!run) {
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
                ProxyNDP.CacheData arpresult =
                    proxyndp.getdiscovercache(Ip4Address.valueOf(ipv4Pkt.getSourceAddress()));
                run = arpresult != null && arpresult.getMac().equals(srcmac);
            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6Pkt = (IPv6) ethPkt.getPayload();
                ProxyNDP.CacheData ndpresult =
                    proxyndp.getdiscovercache(Ip6Address.valueOf(ipv6Pkt.getSourceAddress()));
                run = ndpresult != null && ndpresult.getMac().equals(srcmac);
            }
        }
        if (run) {
            newhostentry(srcmac, deviceId, fromport);
        }
    }

    public void newhostentry(MacAddress mac, DeviceId deviceId, PortNumber port) {
        lock.writeLock().lock();
        try {
            Map<MacAddress, HostEntry> mactable = mactables.get(deviceId);
            if (mactable == null) {
                mactable = new HashMap<>();
                mactables.put(deviceId, mactable);
            }
            HostEntry entry = new HostEntry(deviceId, port, mac);
            if (!entry.equals(mactable.get(mac))) {
                mactable.put(mac, entry);
                log.info("Add an entry to the port table of `{}`. MAC address: `{}` => Port: `{}`.",
                        deviceId, mac, port);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public HostEntry gethostentry(DeviceId deviceId, MacAddress mac) {
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

    public HostEntry buildhostentry(DeviceId targetdeviceId, MacAddress mac) {
        HostEntry start = null;
        for (Device device : deviceService.getDevices()) {
            start = gethostentry(device.id(), mac);
            if (start != null) {
                break;
            }
        }
        if (start == null) {
            return null;
        }

        Set<DeviceId> existdevices = new HashSet<>();
        List<DeviceId> tmpdevices = new ArrayList<>();
        tmpdevices.add(start.getDeviceId());
        existdevices.add(start.getDeviceId());
        while (gethostentry(targetdeviceId, mac) == null &&
                tmpdevices.size() > 0) {
            List<DeviceId> tmp = tmpdevices;
            tmpdevices = new ArrayList<>();
            for (DeviceId tmpdevice : tmp) {
                for (Link link : linkService.getDeviceLinks(tmpdevice)) {
                    DeviceId neighbor;
                    PortNumber ingressPort;
                    if (link.src().deviceId().equals(tmpdevice)) {
                        neighbor = link.dst().deviceId();
                        ingressPort = link.dst().port();
                    } else {
                        neighbor = link.src().deviceId();
                        ingressPort = link.src().port();
                    }

                    if (existdevices.contains(neighbor)) {
                        continue;
                    }

                    if (gethostentry(neighbor, mac) == null) {
                        newhostentry(mac, neighbor, ingressPort);
                    }

                    existdevices.add(neighbor);
                    tmpdevices.add(neighbor);
                }
            }
        }
        return gethostentry(targetdeviceId, mac);
    }
}
