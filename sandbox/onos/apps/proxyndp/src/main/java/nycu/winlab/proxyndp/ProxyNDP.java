package nycu.winlab.proxyndp;

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
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.PortNumber;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Device;
import org.onosproject.net.Port;
import org.onosproject.net.Link;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.onlab.util.Tools;
import org.onlab.packet.Ethernet;
import org.onlab.packet.VlanId;
import org.onlab.packet.ARP;
import org.onlab.packet.IPv6;
import org.onlab.packet.ICMP6;
import org.onlab.packet.MacAddress;
import org.onlab.packet.IpAddress;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;
import org.onlab.packet.ndp.NeighborSolicitation;
import org.onlab.packet.ndp.NeighborAdvertisement;
import org.onlab.packet.ndp.NeighborDiscoveryOptions;
import org.onosproject.event.AbstractListenerManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Properties;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;
import java.util.HashSet;
import java.util.Objects;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.nio.ByteBuffer;

//import static org.onlab.util.Tools.get;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = {ProxyNDP.class},
           property = {
           })
@SuppressWarnings("checkstyle:AbbreviationAsWordInName")
public class ProxyNDP extends AbstractListenerManager<MacEvent, MacEventListener> {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final ProxyNDPACLConfigListener cfgListener = new ProxyNDPACLConfigListener();
    private final ConfigFactory<ApplicationId, ProxyNDPACLConfig> factory =
        new ConfigFactory<ApplicationId, ProxyNDPACLConfig>(
            APP_SUBJECT_FACTORY, ProxyNDPACLConfig.class, "ProxyNDPACLConfig") {
        @Override
        public ProxyNDPACLConfig createConfig() {
            return new ProxyNDPACLConfig();
        }
    };

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    private ApplicationId appId;

    private DiscoverPacketProcessor processor;

    private final DeviceListener devicelistener = new ProxyNDPDeviceListener();

    private Map<DiscoverEntry, HostEntry> maccache = new HashMap<>();
    private Map<IpAddress, CacheData> discovercache = new HashMap<>();

    private ReadWriteLock discoverlock = new ReentrantReadWriteLock();
    private ReadWriteLock maclock = new ReentrantReadWriteLock();

    private ScheduledExecutorService executor;

    private List<AclRule> inputRules = new ArrayList<>();
    private List<AclRule> outputRules = new ArrayList<>();

    @Activate
    protected void activate() {
        if (coreService == null || packetService == null || cfgService == null) {
            return;
        }
        appId = coreService.registerApplication("nycu.winlab.proxyndp");
        cfgService.addListener(cfgListener);
        cfgService.registerConfigFactory(factory);
        deviceService.addListener(devicelistener);
        processor = new DiscoverPacketProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(1));
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV6).matchIPProtocol(IPv6.PROTOCOL_ICMP6);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        eventDispatcher.addSink(MacEvent.class, listenerRegistry);

        executor = Executors.newSingleThreadScheduledExecutor(Tools.groupedThreads(
                    "nycu.winlab.proxyndp",
                    "timeouthandler",
                    log));
        executor.scheduleAtFixedRate(this::timeouthandler, 0, 1, TimeUnit.SECONDS);

        for (Device device : deviceService.getDevices()) {
            initflow(device.id());
        }
    }

    @Deactivate
    protected void deactivate() {
        if (coreService == null || packetService == null || cfgService == null) {
            return;
        }
        if (executor != null) {
            executor.shutdownNow();
        }
        cfgService.removeListener(cfgListener);
        cfgService.unregisterConfigFactory(factory);
        deviceService.removeListener(devicelistener);
        flowRuleService.removeFlowRulesById(appId);
        eventDispatcher.removeSink(MacEvent.class);
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        packetService.removeProcessor(processor);
        processor = null;
        maccache.clear();
        discovercache.clear();
    }

    private void timeouthandler() {
        try {
            cleancache(maccache, maclock);
            cleancache(discovercache, discoverlock);
        } catch (Exception e) {
            log.warn("Timeout handler failed", e);
        }
    }

    private <K, V extends Cache> void cleancache(Map<K, V> map, ReadWriteLock lock) {
        lock.writeLock().lock();
        try {
            Iterator<Map.Entry<K, V>> it = map.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<K, V> e = it.next();
                V value = e.getValue();
                value.decay();
                if (value.isExpired()) {
                    it.remove();
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        //if (context != null) {
        //}
    }

    private boolean aclcheck(Ethernet ethPkt, ConnectPoint point,
            String table, DiscoverEntry discoverentry, boolean request) {
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
            //log.info("Test acl {} {} {} {} {} {} {} {} {} {}", table, rule.rule, point,
            //        discoverentry.getSenderIp(),
            //        discoverentry.getTargetIp(),
            //        rule.device,
            //        rule.port,
            //        rule.sender,
            //        rule.target,
            //        rule.match(point,
            //                   discoverentry.getSenderIp(),
            //                   discoverentry.getTargetIp(),
            //                   request)
            //        );
            if (rule.match(point,
                           discoverentry.getSenderIp(),
                           discoverentry.getTargetIp(),
                           request)) {
                switch (rule.rule) {
                    case "accept":
                        return true;
                    case "deny":
                        return false;
                    case "replytargetmac":
                        if (table.equalsIgnoreCase("input") && request) {
                            discoverentry.setTargetMac(MacAddress.valueOf(rule.data));
                            discoverentry.setOption(discoverentry.defaultOption());
                            Ethernet ethReply = discoverentry.buildReply(ethPkt);
                            if (!aclcheck(ethReply, point, "output", discoverentry, false)) {
                                return false;
                            }
                            TrafficTreatment treatment = DefaultTrafficTreatment.builder().
                                setOutput(point.port()).build();
                            OutboundPacket outPkt = new DefaultOutboundPacket(
                                    point.deviceId(),
                                    treatment,
                                    ByteBuffer.wrap(ethReply.serialize())
                            );
                            packetService.emit(outPkt);
                            return false;
                        }
                        break;
                    default:
                        break;
                }
            }
        }
        return true;
    }

    private class DiscoverPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null) {
                return;
            }
            MacAddress srcmac = ethPkt.getSourceMAC();
            MacAddress dstmac = ethPkt.getDestinationMAC();
            DeviceId deviceId = pkt.receivedFrom().deviceId();
            PortNumber fromport = pkt.receivedFrom().port();
            boolean isrequest = false;
            DiscoverEntry discoverentry = null;
            String pkttype = "";
            String requestmsg = "";
            if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
                ARP arp = (ARP) ethPkt.getPayload();
                short opCode = arp.getOpCode();
                discoverentry = new ArpEntry(arp);
                isrequest = opCode == ARP.OP_REQUEST;
                if (opCode != ARP.OP_REQUEST && opCode != ARP.OP_REPLY) {
                    return;
                }
                pkttype = "ARP";
                requestmsg = "request";
            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6Pkt = (IPv6) ethPkt.getPayload();
                if (ipv6Pkt.getNextHeader() != IPv6.PROTOCOL_ICMP6) {
                    return;
                }
                ICMP6 icmp6Pkt = (ICMP6) ipv6Pkt.getPayload();
                byte type = icmp6Pkt.getIcmpType();
                byte code = icmp6Pkt.getIcmpCode();
                isrequest = type == ICMP6.NEIGHBOR_SOLICITATION;
                if (code != 0) {
                    return;
                }
                if (type == ICMP6.NEIGHBOR_SOLICITATION) {
                    discoverentry = new NdpEntry(srcmac, Ip6Address.valueOf(ipv6Pkt.getSourceAddress()), icmp6Pkt);
                } else if (type == ICMP6.NEIGHBOR_ADVERTISEMENT) {
                    discoverentry = new NdpEntry(dstmac, Ip6Address.valueOf(ipv6Pkt.getDestinationAddress()), icmp6Pkt);
                } else {
                    return;
                }
                pkttype = "NDP";
                requestmsg = "NDP Solicitation";
            } else {
                return;
            }
            try {
                if (isrequest) {
                    ConnectPoint frompoint = new ConnectPoint(deviceId, fromport);
                    if (!aclcheck(ethPkt, frompoint, "input", discoverentry, true)) {
                        return;
                    }
                    log.info("Cache request {} {} -> {} {} from {}", discoverentry.getSenderIp(),
                            discoverentry.getSenderMac(), discoverentry.getTargetIp(),
                            discoverentry.getTargetMac(), frompoint);
                    newdiscovercache(discoverentry.getSenderIp(), new CacheData(discoverentry.getSenderMac(),
                                discoverentry.getOption()));
                    CacheData targetcache = getdiscovercache(discoverentry.getTargetIp());
                    if (targetcache == null) {
                        boolean cacheresult = newmaccache(context);
                        byte[] data = ethPkt.serialize();

                        Set<ConnectPoint> nonEdge = new HashSet<>();
                        for (Link link : linkService.getLinks()) {
                            nonEdge.add(link.src());
                            nonEdge.add(link.dst());
                        }
                        for (Device device : deviceService.getDevices()) {
                            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
                            for (Port port : deviceService.getPorts(device.id())) {
                                ConnectPoint outpoint = new ConnectPoint(device.id(), port.number());
                                if (port.number().equals(PortNumber.LOCAL) ||
                                    outpoint.equals(frompoint) ||
                                    nonEdge.contains(outpoint)) {
                                    continue;
                                }
                                if (!aclcheck(ethPkt, outpoint, "output", discoverentry, true)) {
                                    continue;
                                }
                                treatment.setOutput(port.number());
                            }
                            OutboundPacket outPkt = new DefaultOutboundPacket(
                                    device.id(),
                                    treatment.build(),
                                    ByteBuffer.wrap(data)
                            );
                            packetService.emit(outPkt);
                        }
                        if (cacheresult) {
                            log.info("{} TABLE MISS. Send {} to edge ports", pkttype, requestmsg);
                        }
                    } else if (!targetcache.getMac().equals(discoverentry.getSenderMac())) {
                        ConnectPoint outpoint = new ConnectPoint(deviceId, fromport);

                        discoverentry.setTargetMac(targetcache.getMac());
                        discoverentry.setOption(targetcache.getOption());
                        Ethernet ethReply = discoverentry.buildReply(ethPkt);

                        if (!aclcheck(ethReply, outpoint, "output", discoverentry, false)) {
                            return;
                        }

                        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(fromport).build();
                        OutboundPacket outPkt = new DefaultOutboundPacket(
                                deviceId,
                                treatment,
                                ByteBuffer.wrap(ethReply.serialize())
                        );
                        packetService.emit(outPkt);
                        log.info("{} TABLE HIT. Requested MAC = {}", pkttype, discoverentry.getTargetMac());
                    }
                } else {
                    ConnectPoint frompoint = new ConnectPoint(deviceId, fromport);
                    if (!aclcheck(ethPkt, frompoint, "input", discoverentry, false)) {
                        return;
                    }
                    log.info("Cache reply {} {} -> {} {} from {}", discoverentry.getSenderIp(),
                            discoverentry.getSenderMac(), discoverentry.getTargetIp(),
                            discoverentry.getTargetMac(), frompoint);
                    newdiscovercache(discoverentry.getTargetIp(), new CacheData(discoverentry.getTargetMac(),
                                discoverentry.getOption()));
                    log.info("{} RECV REPLY. Requested MAC = {}", pkttype, discoverentry.getTargetMac());
                    HostEntry dst = getmaccache(discoverentry);
                    if (dst != null) {
                        ConnectPoint outpoint = new ConnectPoint(dst.getDeviceId(), dst.getPort());
                        if (!aclcheck(ethPkt, outpoint, "output", discoverentry, false)) {
                            return;
                        }
                        byte[] data = ethPkt.serialize();
                        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                            .setOutput(dst.getPort())
                            .build();
                        OutboundPacket outPkt = new DefaultOutboundPacket(
                                dst.getDeviceId(),
                                treatment,
                                ByteBuffer.wrap(data)
                        );
                        packetService.emit(outPkt);
                    }
                }
            } finally {
                context.block();
            }
        }
    }

    public void sendrequest(IpAddress sender, MacAddress sendermac, IpAddress target) {
        DiscoverEntry discoverentry = null;
        if (target.isIp4()) {
            discoverentry = new ArpEntry(sender, sendermac, target, MacAddress.ZERO);
        } else if (target.isIp6()) {
            discoverentry = new NdpEntry(sender, sendermac, target, MacAddress.ZERO);
        }

        Ethernet ethPkt = discoverentry.buildRequest();
        byte[] data = ethPkt.serialize();

        Set<ConnectPoint> nonEdge = new HashSet<>();
        for (Link link : linkService.getLinks()) {
            nonEdge.add(link.src());
            nonEdge.add(link.dst());
        }
        for (Device device : deviceService.getDevices()) {
            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
            for (Port port : deviceService.getPorts(device.id())) {
                ConnectPoint outpoint = new ConnectPoint(device.id(), port.number());
                if (port.number().equals(PortNumber.LOCAL) ||
                    nonEdge.contains(outpoint)) {
                    continue;
                }
                if (!aclcheck(ethPkt, outpoint, "output", discoverentry, true)) {
                    continue;
                }
                treatment.setOutput(port.number());
            }
            OutboundPacket outPkt = new DefaultOutboundPacket(
                    device.id(),
                    treatment.build(),
                    ByteBuffer.wrap(data)
            );
            packetService.emit(outPkt);
        }
    }

    private void initflow(DeviceId deviceId) {
        TrafficSelector selector = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_ARP)
            .build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
            .setOutput(PortNumber.CONTROLLER)
            .build();
        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder().
            withSelector(selector).
            withTreatment(treatment).
            withPriority(30000).
            withFlag(ForwardingObjective.Flag.VERSATILE).
            fromApp(appId).
            makePermanent().
            add();
        flowObjectiveService.forward(deviceId, forwardingObjective);

        selector = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV6)
            .matchIPProtocol(IPv6.PROTOCOL_ICMP6)
            .matchIcmpv6Type((byte) 135)
            .build();
        treatment = DefaultTrafficTreatment.builder()
            .setOutput(PortNumber.CONTROLLER)
            .build();
        forwardingObjective = DefaultForwardingObjective.builder().
            withSelector(selector).
            withTreatment(treatment).
            withPriority(30000).
            withFlag(ForwardingObjective.Flag.VERSATILE).
            fromApp(appId).
            makePermanent().
            add();
        flowObjectiveService.forward(deviceId, forwardingObjective);

        selector = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV6)
            .matchIPProtocol(IPv6.PROTOCOL_ICMP6)
            .matchIcmpv6Type((byte) 136)
            .build();
        treatment = DefaultTrafficTreatment.builder()
            .setOutput(PortNumber.CONTROLLER)
            .build();
        forwardingObjective = DefaultForwardingObjective.builder().
            withSelector(selector).
            withTreatment(treatment).
            withPriority(30000).
            withFlag(ForwardingObjective.Flag.VERSATILE).
            fromApp(appId).
            makePermanent().
            add();
        flowObjectiveService.forward(deviceId, forwardingObjective);

        selector = DefaultTrafficSelector.builder()
            .matchEthType((short) 0x8942)
            .build();
        treatment = DefaultTrafficTreatment.builder()
            .setOutput(PortNumber.CONTROLLER)
            .build();
        forwardingObjective = DefaultForwardingObjective.builder().
            withSelector(selector).
            withTreatment(treatment).
            withPriority(30000).
            withFlag(ForwardingObjective.Flag.VERSATILE).
            fromApp(appId).
            makePermanent().
            add();
        flowObjectiveService.forward(deviceId, forwardingObjective);
    }

    @SuppressWarnings("checkstyle:AbbreviationAsWordInName")
    private class ProxyNDPACLConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
                    && event.configClass().equals(ProxyNDPACLConfig.class)) {
                ProxyNDPACLConfig config = cfgService.getConfig(appId, ProxyNDPACLConfig.class);
                if (config != null) {
                    inputRules = config.getInputRules();
                    outputRules = config.getOutputRules();
                }
            }
        }
    }

    @SuppressWarnings("checkstyle:AbbreviationAsWordInName")
    private class ProxyNDPDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            Device device = event.subject();
            switch (event.type()) {
                case DEVICE_ADDED:
                    initflow(device.id());
                    break;
                default:
                    break;
            }
        }
    }

    private boolean newmaccache(PacketContext context) {
        InboundPacket pkt = context.inPacket();
        Ethernet ethPkt = pkt.parsed();
        MacAddress srcmac = ethPkt.getSourceMAC();
        DeviceId deviceId = pkt.receivedFrom().deviceId();
        PortNumber fromport = pkt.receivedFrom().port();
        DiscoverEntry discoverentry = null;
        if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
            ARP arp = (ARP) ethPkt.getPayload();
            discoverentry = new ArpEntry(arp);
        } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
            IPv6 ipv6Pkt = (IPv6) ethPkt.getPayload();
            if (ipv6Pkt.getNextHeader() != IPv6.PROTOCOL_ICMP6) {
                return false;
            }
            ICMP6 icmp6Pkt = (ICMP6) ipv6Pkt.getPayload();
            byte type = icmp6Pkt.getIcmpType();
            byte code = icmp6Pkt.getIcmpCode();
            if (type != ICMP6.NEIGHBOR_SOLICITATION) {
                return false;
            }
            discoverentry = new NdpEntry(srcmac, Ip6Address.valueOf(ipv6Pkt.getSourceAddress()), icmp6Pkt);
        } else {
            return false;
        }
        maclock.writeLock().lock();
        boolean result = false;
        try {
            if (!maccache.containsKey(discoverentry)) {
                maccache.put(discoverentry, new HostEntry(deviceId, fromport, srcmac));
                result = true;
            } else {
                maccache.get(discoverentry).reset();
            }
        } finally {
            maclock.writeLock().unlock();
        }
        return result;
    }

    private HostEntry getmaccache(DiscoverEntry discoverentry) {
        HostEntry result = null;
        maclock.writeLock().lock();
        try {
            result = maccache.get(discoverentry);
            if (result != null) {
                maccache.remove(discoverentry);
            }
        } finally {
            maclock.writeLock().unlock();
        }
        return result;
    }

    private void newdiscovercache(IpAddress ip, CacheData cache) {
        boolean change = false;
        discoverlock.writeLock().lock();
        try {
            CacheData result = discovercache.get(ip);
            change = (result == null || !result.getMac().equals(cache.getMac()));
            discovercache.put(ip, cache);
        } finally {
            discoverlock.writeLock().unlock();
        }
        if (change) {
            post(new MacEvent(MacEventType.UPDATE, new IpMac(ip, cache.getMac())));
        }
    }

    public CacheData getdiscovercache(IpAddress targetIp) {
        CacheData result = null;
        discoverlock.writeLock().lock();
        try {
            result = discovercache.get(targetIp);
            if (result != null) {
                result.reset();
            }
        } finally {
            discoverlock.writeLock().unlock();
        }
        return result;
    }

    private abstract class Cache {
        private int life;
        private int defaultlife = 5;

        public Cache(int defaultlife) {
            this.defaultlife = defaultlife;
            life = defaultlife;
        }

        public void reset() {
            life = defaultlife;
        }

        public void decay() {
            life -= 1;
        }

        public boolean isExpired() {
            return life <= 0;
        }
    }

    public class CacheData extends Cache {
        private MacAddress mac;
        private Object option;
        public CacheData(MacAddress mac, Object option) {
            super(3600);
            this.mac = mac;
            this.option = option;
        }
        public MacAddress getMac() {
            return mac;
        }
        public Object getOption() {
            return option;
        }
    }
    private class HostEntry extends Cache {
        private MacAddress mac;
        private DeviceId deviceId;
        private PortNumber port;
        public HostEntry(DeviceId deviceId, PortNumber port, MacAddress mac) {
            super(5);
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
    }

    private abstract class DiscoverEntry {
        protected MacAddress senderMac;
        protected MacAddress targetMac;
        protected IpAddress senderIp;
        protected IpAddress targetIp;
        protected Object option;

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            DiscoverEntry discover = (DiscoverEntry) o;
            return senderMac.equals(discover.senderMac) &&
                senderIp.equals(discover.senderIp) &&
                targetIp.equals(discover.targetIp);
        }

        @Override
        public int hashCode() {
            return Objects.hash(senderMac, senderIp, targetIp);
        }

        public MacAddress getSenderMac() {
            return senderMac;
        }

        public MacAddress getTargetMac() {
            return targetMac;
        }

        public void setTargetMac(MacAddress targetMac) {
            this.targetMac = targetMac;
        }

        public IpAddress getSenderIp() {
            return senderIp;
        }

        public IpAddress getTargetIp() {
            return targetIp;
        }

        public Object getOption() {
            return option;
        }

        public void setOption(Object option) {
            this.option = option;
        }

        public Object defaultOption() {
            return null;
        }

        public Ethernet buildReply(Ethernet request) {
            return null;
        }

        public Ethernet buildRequest() {
            return null;
        }
    }

    private class ArpEntry extends DiscoverEntry {
        public ArpEntry(ARP arp) {
            short opCode = arp.getOpCode();
            if (opCode == ARP.OP_REQUEST) {
                senderMac = MacAddress.valueOf(arp.getSenderHardwareAddress());
                targetMac = MacAddress.valueOf(arp.getTargetHardwareAddress());
                senderIp = Ip4Address.valueOf(arp.getSenderProtocolAddress());
                targetIp = Ip4Address.valueOf(arp.getTargetProtocolAddress());
            } else if (opCode == ARP.OP_REPLY) {
                targetMac = MacAddress.valueOf(arp.getSenderHardwareAddress());
                senderMac = MacAddress.valueOf(arp.getTargetHardwareAddress());
                targetIp = Ip4Address.valueOf(arp.getSenderProtocolAddress());
                senderIp = Ip4Address.valueOf(arp.getTargetProtocolAddress());
            }
        }

        public ArpEntry(IpAddress senderIp, MacAddress senderMac, IpAddress targetIp, MacAddress targetMac) {
            this.senderIp = senderIp;
            this.senderMac = senderMac;
            this.targetIp = targetIp;
            this.targetMac = targetMac;
        }

        @Override
        public Ethernet buildReply(Ethernet request) {
            return ARP.buildArpReply((Ip4Address) targetIp, targetMac, request);
        }

        @Override
        public Ethernet buildRequest() {
            return ARP.buildArpRequest(senderMac.toBytes(),
                    senderIp.toOctets(),
                    targetIp.toOctets(),
                    VlanId.NONE.toShort());
        }
    }

    private class NdpEntry extends DiscoverEntry {
        private boolean isdad = false;

        public NdpEntry(IpAddress senderIp, MacAddress senderMac, IpAddress targetIp, MacAddress targetMac) {
            this.senderIp = senderIp;
            this.senderMac = senderMac;
            this.targetIp = targetIp;
            this.targetMac = targetMac;
            option = false;
        }

        public NdpEntry(MacAddress senderMac, Ip6Address senderIp, ICMP6 ndp) {
            byte type = ndp.getIcmpType();
            byte code = ndp.getIcmpCode();
            option = false;
            if (type == ICMP6.NEIGHBOR_SOLICITATION) {
                NeighborSolicitation ns = (NeighborSolicitation) ndp.getPayload();
                this.senderMac = MacAddress.ZERO;
                for (NeighborDiscoveryOptions.Option opt : ns.getOptions()) {
                    if (opt.type() == NeighborDiscoveryOptions.TYPE_SOURCE_LL_ADDRESS) {
                        this.senderMac = MacAddress.valueOf(opt.data());
                    }
                }
                if (this.senderMac.equals(MacAddress.ZERO)) {
                    isdad = true;
                    this.senderMac = senderMac;
                }
                this.targetMac = MacAddress.ZERO;
                this.senderIp = senderIp;
                targetIp = Ip6Address.valueOf(ns.getTargetAddress());
            } else if (type == ICMP6.NEIGHBOR_ADVERTISEMENT) {
                NeighborAdvertisement na = (NeighborAdvertisement) ndp.getPayload();
                this.senderMac = senderMac;
                this.targetMac = MacAddress.ZERO;
                for (NeighborDiscoveryOptions.Option opt : na.getOptions()) {
                    if (opt.type() == NeighborDiscoveryOptions.TYPE_TARGET_LL_ADDRESS) {
                        this.targetMac = MacAddress.valueOf(opt.data());
                    }
                }
                this.senderIp = senderIp;
                targetIp = Ip6Address.valueOf(na.getTargetAddress());
                option = na.getRouterFlag() != 0;
            }
        }

        @Override
        public Ethernet buildReply(Ethernet request) {
            Ethernet reply = NeighborAdvertisement.buildNdpAdv((Ip6Address) targetIp, targetMac, request);
            IPv6 ipv6Pkt = (IPv6) reply.getPayload();
            ipv6Pkt.setHopLimit((byte) 0xff);
            ICMP6 icmp6Pkt = (ICMP6) ipv6Pkt.getPayload();
            NeighborAdvertisement na = (NeighborAdvertisement) icmp6Pkt.getPayload();
            na.setRouterFlag((byte) ((boolean) option ? 1 : 0));
            na.setSolicitedFlag((byte) (!isdad ? 1 : 0));
            na.setOverrideFlag((byte) 1);
            return reply;
        }

        @Override
        public Ethernet buildRequest() {
            byte[] targetIpByte = targetIp.toOctets();
            byte[] dstipbyte = Ip6Address.valueOf("ff02::1:ff00:0000").toOctets();
            dstipbyte[13] = targetIpByte[13];
            dstipbyte[14] = targetIpByte[14];
            dstipbyte[15] = targetIpByte[15];
            byte[] dstmacbyte = MacAddress.valueOf("33:33:ff:00:00:00").toBytes();
            dstmacbyte[3] = targetIpByte[13];
            dstmacbyte[4] = targetIpByte[14];
            dstmacbyte[5] = targetIpByte[15];
            return NeighborSolicitation.buildNdpSolicit((Ip6Address) targetIp,
                    (Ip6Address) senderIp,
                    Ip6Address.valueOf(dstipbyte),
                    senderMac,
                    MacAddress.valueOf(dstmacbyte),
                    VlanId.NONE);
        }

        @Override
        public Object defaultOption() {
            return false;
        }
    }
}
