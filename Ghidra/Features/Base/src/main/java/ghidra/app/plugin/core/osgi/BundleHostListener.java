package ghidra.app.plugin.core.osgi;

import java.util.Collection;

/**
 * Listener for OSGi framework events.
 */
public interface BundleHostListener {

	default void bundleBuilt(GhidraBundle gbundle) {
		//
	}

	default void bundleEnablementChange(GhidraBundle gbundle, boolean newEnablement) {
		//
	}

	default void bundleActivationChange(GhidraBundle gbundle, boolean newActivation) {
		//
	}

	default void bundleAdded(GhidraBundle gbundle) {
		//
	}

	default void bundlesAdded(Collection<GhidraBundle> gbundles) {
		for (GhidraBundle gbundle : gbundles) {
			bundleAdded(gbundle);
		}
	}

	default void bundleRemoved(GhidraBundle gbundle) {
		//
	}

	default void bundlesRemoved(Collection<GhidraBundle> gbundles) {
		for (GhidraBundle gbundle : gbundles) {
			bundleRemoved(gbundle);
		}
	}

}
