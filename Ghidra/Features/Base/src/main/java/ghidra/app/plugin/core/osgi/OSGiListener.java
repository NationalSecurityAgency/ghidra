package ghidra.app.plugin.core.osgi;

import org.osgi.framework.Bundle;

/**
 * Listener for OSGi framework events.
 */
public interface OSGiListener {

	default void bundleBuilt(GhidraBundle gb) {
		//
	}

	default void bundleActivationChange(Bundle b, boolean newActivation) {
		//
	}
}
