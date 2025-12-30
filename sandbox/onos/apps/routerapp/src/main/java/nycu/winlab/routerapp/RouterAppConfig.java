package nycu.winlab.routerapp;

import com.fasterxml.jackson.databind.JsonNode;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.config.Config;
import org.onlab.packet.IpAddress;
import org.onlab.packet.IpPrefix;
import org.onosproject.routeservice.Route;
import java.util.List;
import java.util.ArrayList;


@SuppressWarnings("checkstyle:AbbreviationAsWordInName")
public class RouterAppConfig
        extends Config<ApplicationId> {

    public static final String DEFAULTCONNECT = "defaultconnect";
    public static final String DEFAULTLINKLOCAL = "defaultlinklocal";
    public static final String IXPEERV4 = "ixpeerv4";
    public static final String IXPEERV6 = "ixpeerv6";
    public static final String CONNECTS = "connects";
    public static final String ROUTES = "routes";

    @Override
    public boolean isValid() {
        return hasOnlyFields(DEFAULTCONNECT, DEFAULTLINKLOCAL, IXPEERV4, IXPEERV6, CONNECTS, ROUTES);
    }

    public IpInfo getDefaultConnect() {
        return new IpInfo(IpAddress.valueOf(object.get(DEFAULTCONNECT).asText().split("/")[0]),
            IpPrefix.valueOf(object.get(DEFAULTCONNECT).asText()));
    }

    public IpAddress getDefaultLinkLocal() {
        return IpAddress.valueOf(object.get(DEFAULTLINKLOCAL).asText());
    }

    public IpAddress getIxPeerV4() {
        return IpAddress.valueOf(object.get(IXPEERV4).asText());
    }

    public IpAddress getIxPeerV6() {
        return IpAddress.valueOf(object.get(IXPEERV6).asText());
    }

    public List<IpInfo> getConnects() {
        List<IpInfo> connects = new ArrayList<>();
        JsonNode array = object.get(CONNECTS);
        if (array == null) {
            return connects;
        }
        for (JsonNode n : array) {
            connects.add(new IpInfo(IpAddress.valueOf(n.asText().split("/")[0]), IpPrefix.valueOf(n.asText())));
        }
        return connects;
    }

    public List<Route> getRoutes() {
        List<Route> routes = new ArrayList<>();
        JsonNode array = object.get(CONNECTS);
        if (array == null) {
            return routes;
        }
        for (JsonNode n : array) {
            routes.add(new Route(Route.Source.STATIC,
                                 IpPrefix.valueOf(n.get("prefix").asText()),
                                 IpAddress.valueOf(n.get("gateway").asText())));
        }
        return routes;
    }
}

