package nycu.winlab.bridgeapp;

import org.onosproject.core.ApplicationId;
import org.onosproject.net.config.Config;
import java.util.List;


@SuppressWarnings("checkstyle:AbbreviationAsWordInName")
public class BridgeAppInitConfig
        extends Config<ApplicationId> {

    public static final String HOSTENTRY = "hostentry";

    @Override
    public boolean isValid() {
        return hasOnlyFields(HOSTENTRY);
    }

    public List<HostEntry> getHostEntry() {
        return HostEntry.parse(object.get(HOSTENTRY));
    }
}

