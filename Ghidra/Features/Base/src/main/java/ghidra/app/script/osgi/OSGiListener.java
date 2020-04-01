package ghidra.app.script.osgi;

import org.osgi.framework.Bundle;

public interface OSGiListener {

	void sourceBundleCompiled(SourceBundleInfo sbi);

	void bundleActivationChange(Bundle b, boolean newActivation);
}
