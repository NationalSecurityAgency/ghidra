package ghidra.app.plugin.core.osgi;

import org.osgi.framework.Bundle;

public interface OSGiListener {

	default void bundleBuilt(GhidraBundle gb) {
		//
	}

	default void bundleActivationChange(Bundle b, boolean newActivation) {
		//
	}
}
