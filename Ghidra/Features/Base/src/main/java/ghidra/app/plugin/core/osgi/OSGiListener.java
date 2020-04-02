package ghidra.app.plugin.core.osgi;

import org.osgi.framework.Bundle;

public interface OSGiListener {

	void sourceBundleCompiled(GhidraSourceBundle sb);

	void bundleActivationChange(Bundle b, boolean newActivation);
}
