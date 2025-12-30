/*
 * Copyright 2025-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nycu.winlab.routerapp;

import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;

import nycu.winlab.bridgeapp.BridgeApp;
import nycu.winlab.bridgeapp.AclRule;
import nycu.winlab.bridgeapp.HostEntry;
import nycu.winlab.proxyndp.ProxyNDP;
import nycu.winlab.proxyndp.MacEventListener;
import nycu.winlab.proxyndp.MacEvent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
//import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.routeservice.RouteService;
import org.onosproject.routeservice.RouteListener;
import org.onosproject.routeservice.RouteEvent;
import org.onosproject.routeservice.ResolvedRoute;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.PortNumber;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Device;
import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.IpAddress;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.Ip6Address;

import java.util.Dictionary;
import java.util.Properties;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.nio.ByteBuffer;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = {RouterApp.class},
           property = {
           })
public class RouterApp {

    private static final int ROUTEPRIORITY = 4000;
    private static final int BASEPRIORITY = 2000;

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final RouterAppConfigListener cfgListener = new RouterAppConfigListener();

    private final ConfigFactory<ApplicationId, RouterAppConfig> factory =
        new ConfigFactory<ApplicationId, RouterAppConfig>(
            APP_SUBJECT_FACTORY, RouterAppConfig.class, "RouterAppConfig") {
        @Override
        public RouterAppConfig createConfig() {
            return new RouterAppConfig();
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
    protected RouteService routeService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ProxyNDP proxyndp;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected BridgeApp bridgeapp;

    private ApplicationId appId;

    private final DeviceListener devicelistener = new RouterAppDeviceListener();

    private final RouterAppMacEventListener maceventlistener = new RouterAppMacEventListener();

    private final RouteListener routelistener = new RouterAppRouteListener();

    private RoutePacketProcessor processor;

    private List<IpInfo> connects = new ArrayList<>();

    private Map<IpPrefix, TrafficSelector> mactoselector = new HashMap<>();

    private ReadWriteLock routelock = new ReentrantReadWriteLock();

    @Activate
    protected void activate() {
        if (coreService == null || packetService == null || cfgService == null) {
            return;
        }
        appId = coreService.registerApplication("nycu.winlab.routerapp");
        processor = new RoutePacketProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(3));
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        routeService.addListener(routelistener);
        proxyndp.addListener(maceventlistener);
        deviceService.addListener(devicelistener);
        cfgService.addListener(cfgListener);
        cfgService.registerConfigFactory(factory);
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
        routeService.removeListener(routelistener);
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        processor = null;
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
    }

    private class RoutePacketProcessor implements PacketProcessor {
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
            if (ethPkt.getEtherType() != Ethernet.TYPE_IPV4 &&
                ethPkt.getEtherType() != Ethernet.TYPE_IPV6) {
                return;
            }
            if (srcmac.isBroadcast() || srcmac.isMulticast()) {
                return;
            }
            DeviceId deviceId = pkt.receivedFrom().deviceId();
            PortNumber fromport = pkt.receivedFrom().port();
            ConnectPoint frompoint = new ConnectPoint(deviceId, fromport);
            IpAddress sip = null;
            IpAddress dip = null;
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipPkt = (IPv4) ethPkt.getPayload();
                sip = Ip4Address.valueOf(ipPkt.getSourceAddress());
                dip = Ip4Address.valueOf(ipPkt.getDestinationAddress());
            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipPkt = (IPv6) ethPkt.getPayload();
                sip = Ip6Address.valueOf(ipPkt.getSourceAddress());
                dip = Ip6Address.valueOf(ipPkt.getDestinationAddress());
            }
            ProxyNDP.CacheData dstmaccheck = proxyndp.getdiscovercache(dip);
            if (dstmaccheck != null && dstmaccheck.getMac().equals(dstmac)) {
                return;
            }
            boolean doroute = false;
            for (IpInfo tmp : connects) {
                dstmaccheck = proxyndp.getdiscovercache(tmp.getAddress());
                if (dstmaccheck != null && dstmaccheck.getMac().equals(dstmac)) {
                    doroute = true;
                }
            }
            if (!doroute) {
                return;
            }
            IpInfo useconnect = null;
            for (IpInfo tmp : connects) {
                if (tmp.getPrefix().contains(dip)) {
                    useconnect = tmp;
                    break;
                }
            }
            ResolvedRoute route = null;
            if (useconnect == null) {
                Optional<ResolvedRoute> result = routeService.longestPrefixLookup(dip);
                if (!result.isPresent()) {
                    return;
                }
                route = result.get();
                for (IpInfo tmp : connects) {
                    if (tmp.getPrefix().contains(route.nextHop())) {
                        useconnect = tmp;
                        break;
                    }
                }
            }
            if (useconnect == null) {
                return;
            }
            IpAddress nexthop = dip;
            if (route != null) {
                nexthop = route.nextHop();
            }
            dstmaccheck = proxyndp.getdiscovercache(nexthop);
            ProxyNDP.CacheData srcmaccheck = proxyndp.getdiscovercache(useconnect.getAddress());
            if (srcmaccheck == null) {
                return;
            }
            if (dstmaccheck == null) {
                proxyndp.sendrequest(useconnect.getAddress(), srcmaccheck.getMac(), nexthop);
                return;
            }
            addrule(context, route, useconnect);
        }
    }

    private void addrule(PacketContext context, ResolvedRoute route, IpInfo connect) {
        InboundPacket pkt = context.inPacket();
        DeviceId deviceId = pkt.receivedFrom().deviceId();
        PortNumber fromport = pkt.receivedFrom().port();
        ConnectPoint frompoint = new ConnectPoint(deviceId, fromport);
        Ethernet ethPkt = pkt.parsed();
        MacAddress srcmac = ethPkt.getSourceMAC();
        MacAddress dstmac = ethPkt.getDestinationMAC();
        IpAddress sip = null;
        IpAddress dip = null;
        if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
            IPv4 ipPkt = (IPv4) ethPkt.getPayload();
            sip = Ip4Address.valueOf(ipPkt.getSourceAddress());
            dip = Ip4Address.valueOf(ipPkt.getDestinationAddress());
        } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
            IPv6 ipPkt = (IPv6) ethPkt.getPayload();
            sip = Ip6Address.valueOf(ipPkt.getSourceAddress());
            dip = Ip6Address.valueOf(ipPkt.getDestinationAddress());
        }

        boolean tolocal = false;
        for (IpInfo tmp : connects) {
            if (tmp.getAddress().equals(dip)) {
                tolocal = true;
                break;
            }
        }

        IpAddress nexthop = dip;
        if (route != null) {
            nexthop = route.nextHop();
        }
        ProxyNDP.CacheData dstmaccheck = null;
        ProxyNDP.CacheData srcmaccheck = null;
        HostEntry hostentry = null;
        routelock.writeLock().lock();
        TrafficTreatment.Builder treatment = null;
        Ethernet neweth = null;
        try {
            dstmaccheck = proxyndp.getdiscovercache(nexthop);
            srcmaccheck = proxyndp.getdiscovercache(connect.getAddress());
            hostentry = bridgeapp.gethostentry(deviceId, dstmaccheck.getMac());
            if (hostentry == null) {
                hostentry = bridgeapp.buildhostentry(deviceId, dstmaccheck.getMac());
            }

            try {
                neweth = Ethernet.deserializer().deserialize(ethPkt.serialize(), 0, ethPkt.serialize().length);
            } catch (Exception e) {
                return;
            }

            if (!tolocal) {
                neweth.setSourceMACAddress(srcmaccheck.getMac());
            }
            neweth.setDestinationMACAddress(dstmaccheck.getMac());
            if (hostentry == null) {
                treatment = DefaultTrafficTreatment.builder();
                bridgeapp.flood(context, treatment, neweth);
                log.info(
                    "Flood routing {} {} -> {} {}, {} -> {}, match route prefix: {} gateway: {} useconnect: {} on {}",
                    sip, srcmac, dip,
                    dstmac, tolocal ? srcmac : srcmaccheck.getMac(), dstmaccheck.getMac(),
                    route == null ? null : route.prefix(),
                    route == null ? null : route.nextHop(),
                    connect.getAddress(), frompoint);
                return;
            }

            AclRule rule = bridgeapp.aclcheck(neweth, new ConnectPoint(hostentry.getDeviceId(), hostentry.getPort()),
                    "output");
            if (rule.rule.equalsIgnoreCase("deny")) {
                return;
            }

            TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
            selector.matchEthDst(dstmac);
            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                selector.matchEthType(Ethernet.TYPE_IPV4);
                if (route == null) {
                    selector.matchIPDst(IpPrefix.valueOf(dip, 32));
                } else {
                    selector.matchIPDst(route.prefix());
                }
            } else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                selector.matchEthType(Ethernet.TYPE_IPV6);
                if (route == null) {
                    selector.matchIPv6Dst(IpPrefix.valueOf(dip, 128));
                } else {
                    selector.matchIPv6Dst(route.prefix());
                }
            }
            TrafficSelector selectorbuild = selector.build();

            treatment = DefaultTrafficTreatment.builder();
            if (!tolocal) {
                treatment.setEthSrc(srcmaccheck.getMac());
            }
            treatment.setEthDst(dstmaccheck.getMac());
            treatment.setOutput(hostentry.getPort());
            ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder().
                withSelector(selectorbuild).
                withTreatment(treatment.build()).
                withPriority(ROUTEPRIORITY).
                withFlag(ForwardingObjective.Flag.VERSATILE).
                fromApp(appId).
                makeTemporary(300).
                add();
            flowObjectiveService.forward(hostentry.getDeviceId(), forwardingObjective);
            if (route != null) {
                mactoselector.put(route.prefix(), selectorbuild);
            }
        } finally {
            routelock.writeLock().unlock();
        }

        treatment = DefaultTrafficTreatment.builder();
        treatment.setOutput(hostentry.getPort());
        byte[] data = neweth.serialize();
        OutboundPacket outPkt = new DefaultOutboundPacket(
                deviceId,
                treatment.build(),
                ByteBuffer.wrap(data)
        );
        packetService.emit(outPkt);
        context.block();

        log.info(
            "Send routing {} {} -> {} {}, {} -> {}," +
            "match route prefix: {} gateway: {} useconnect: {} on {} to port {}",
            sip, srcmac, dip,
            dstmac, tolocal ? srcmac : srcmaccheck.getMac(), dstmaccheck.getMac(),
            route == null ? null : route.prefix(),
            route == null ? null : route.nextHop(),
            connect.getAddress(), frompoint, hostentry.getPort());
    }

    private void reloadbaseflow() {
        routelock.writeLock().lock();
        try {
            flowRuleService.removeFlowRulesById(appId);
            mactoselector.clear();
            for (IpInfo tmp : connects) {
                log.info("Reload Test config {} {}", tmp.getAddress(), tmp.getPrefix());
                ProxyNDP.CacheData mac = proxyndp.getdiscovercache(tmp.getAddress());
                if (mac != null) {
                    TrafficSelector selector = DefaultTrafficSelector.builder().
                        matchEthDst(mac.getMac()).
                        build();
                    TrafficTreatment treatment = DefaultTrafficTreatment.builder().
                        setOutput(PortNumber.CONTROLLER).
                        build();
                    for (Device device : deviceService.getDevices()) {
                        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder().
                            withSelector(selector).
                            withTreatment(treatment).
                            withPriority(BASEPRIORITY).
                            withFlag(ForwardingObjective.Flag.VERSATILE).
                            fromApp(appId).
                            makePermanent().
                            add();
                        flowObjectiveService.forward(device.id(), forwardingObjective);
                        log.info("Reload Install connect flow {} on {}", mac.getMac(), device.id());
                    }
                } else {
                    log.info("Reload Test config {} {}", tmp.getAddress(), tmp.getPrefix());
                }
            }
        } finally {
            routelock.writeLock().unlock();
        }
    }

    private void removerouteflow(IpPrefix prefix) {
        routelock.writeLock().lock();
        try {
            TrafficSelector selector = mactoselector.remove(prefix);
            if (selector != null) {
                for (Device device : deviceService.getDevices()) {
                    ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder().
                        withSelector(selector).
                        withPriority(ROUTEPRIORITY).
                        withFlag(ForwardingObjective.Flag.VERSATILE).
                        fromApp(appId).
                        remove();
                    flowObjectiveService.forward(device.id(), forwardingObjective);
                }
            }
        } finally {
            routelock.writeLock().unlock();
        }
    }

    private void clearDeviceFlows(DeviceId deviceId) {
        for (FlowRule rule : flowRuleService.getFlowEntries(deviceId)) {
            if (rule.appId() == appId.id()) {
                flowRuleService.removeFlowRules(rule);
            }
        }
        log.info("Clear flow {}", deviceId);
    }

    @SuppressWarnings("checkstyle:AbbreviationAsWordInName")
    private class RouterAppConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            if (event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED) {
                if (event.configClass().equals(RouterAppConfig.class)) {
                    RouterAppConfig config = cfgService.getConfig(appId, RouterAppConfig.class);
                    if (config != null) {
                        connects = config.getConnects();
                        reloadbaseflow();
                    }
                }
            }
        }
    }

    private class RouterAppMacEventListener implements MacEventListener {
        @Override
        public void event(MacEvent macevent) {
            boolean isconnect = false;
            for (IpInfo tmp : connects) {
                log.info("Test mac update {} {}", tmp.getAddress(), macevent.subject().getIp());
                if (tmp.getAddress().equals(macevent.subject().getIp())) {
                    isconnect = true;
                    break;
                }
            }
            if (!isconnect) {
                return;
            }
            reloadbaseflow();
        }
    }

    private class RouterAppDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            Device device = event.subject();
            switch (event.type()) {
                case DEVICE_ADDED:
                    for (IpInfo tmp : connects) {
                        ProxyNDP.CacheData mac = proxyndp.getdiscovercache(tmp.getAddress());
                        if (mac != null) {
                            TrafficSelector selector = DefaultTrafficSelector.builder().
                                matchEthDst(mac.getMac()).
                                build();
                            TrafficTreatment treatment = DefaultTrafficTreatment.builder().
                                setOutput(PortNumber.CONTROLLER).
                                build();
                            ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder().
                                withSelector(selector).
                                withTreatment(treatment).
                                withPriority(BASEPRIORITY).
                                withFlag(ForwardingObjective.Flag.VERSATILE).
                                fromApp(appId).
                                makePermanent().
                                add();
                            flowObjectiveService.forward(device.id(), forwardingObjective);
                            log.info("Install connect flow {} on {}", mac.getMac(), device.id());
                        }
                    }
                    break;
                case DEVICE_REMOVED:
                    clearDeviceFlows(device.id());
                    break;
                default:
                    break;
            }
        }
    }

    private class RouterAppRouteListener implements RouteListener {
        @Override
        public void event(RouteEvent event) {
            ResolvedRoute route = event.subject();
            switch (event.type()) {
                case ROUTE_ADDED:
                    break;
                case ROUTE_REMOVED:
                    removerouteflow(route.prefix());
                    break;
                case ROUTE_UPDATED:
                    removerouteflow(route.prefix());
                    break;
                default:
                    break;
            }
        }
    }
}
