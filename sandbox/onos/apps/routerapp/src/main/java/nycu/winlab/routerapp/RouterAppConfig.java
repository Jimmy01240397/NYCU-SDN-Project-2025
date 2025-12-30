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

    public static final String CONNECTS = "connects";
    public static final String ROUTES = "routes";

    @Override
    public boolean isValid() {
        return hasOnlyFields(CONNECTS, ROUTES);
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

