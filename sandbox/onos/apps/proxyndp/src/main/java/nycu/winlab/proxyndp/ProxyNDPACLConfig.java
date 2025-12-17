package nycu.winlab.proxyndp;

import org.onosproject.core.ApplicationId;
import org.onosproject.net.config.Config;
import java.util.List;


@SuppressWarnings("checkstyle:AbbreviationAsWordInName")
public class ProxyNDPACLConfig
        extends Config<ApplicationId> {

    public static final String INPUT = "input";
    public static final String OUTPUT = "output";

    @Override
    public boolean isValid() {
        return hasOnlyFields(INPUT, OUTPUT);
    }

    public List<AclRule> getInputRules() {
        return AclRule.parse(object.get(INPUT));
    }

    public List<AclRule> getOutputRules() {
        return AclRule.parse(object.get(OUTPUT));
    }
}

