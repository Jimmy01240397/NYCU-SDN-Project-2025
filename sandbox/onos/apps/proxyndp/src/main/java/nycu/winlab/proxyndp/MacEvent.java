package nycu.winlab.proxyndp;

import org.onosproject.event.AbstractEvent;

public class MacEvent extends AbstractEvent<MacEventType, IpMac> {
    public MacEvent(MacEventType type, IpMac ipmac) {
        super(type, ipmac);
    }
}


