package ghidra.app.plugin.core.osgi;

import java.io.File;
import java.io.PrintWriter;
import java.util.List;

import org.osgi.framework.Bundle;
import org.osgi.framework.wiring.BundleRequirement;

import generic.jar.ResourceFile;

public abstract class GhidraBundle {

	protected final ResourceFile path;
	protected final BundleHost bundleHost;
	protected boolean enabled;
	protected boolean systemBundle;

	GhidraBundle(BundleHost bundleHost, ResourceFile path, boolean enabled, boolean systemBundle) {
		this.bundleHost = bundleHost;
		this.path = path;
		this.enabled = enabled;
		this.systemBundle = systemBundle;
	}

	/**
	 * clean build artifacts generated during build of this bundle
	 * 
	 * @return true if anything was done
	 */
	abstract boolean clean();

	/**
	 * build OSGi bundle if possible
	 *  
	 * @param writer console for user messages 
	 * @return true if build happened, false if already built
	 * @throws Exception sorry, wasn't possible
	 */
	abstract boolean build(PrintWriter writer) throws Exception;

	abstract String getSummary();

	abstract String getBundleLoc();

	abstract List<BundleRequirement> getAllReqs();

	public ResourceFile getPath() {
		return path;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public boolean isSystemBundle() {
		return systemBundle;
	}

	enum Type {
		BndScript, Jar, SourceDir, INVALID
	}

	static GhidraBundle.Type getType(ResourceFile rf) {
		if (rf.isDirectory()) {
			return GhidraBundle.Type.SourceDir;
		}
		String n = rf.getName().toLowerCase();
		if (n.endsWith(".bnd")) {
			return GhidraBundle.Type.BndScript;
		}
		if (n.endsWith(".jar")) {
			return GhidraBundle.Type.Jar;
		}
		return GhidraBundle.Type.INVALID;
	}

	static public GhidraBundle.Type getType(File f) {
		if (f.isDirectory()) {
			return GhidraBundle.Type.SourceDir;
		}
		String n = f.getName().toLowerCase();
		if (n.endsWith(".bnd")) {
			return GhidraBundle.Type.BndScript;
		}
		if (n.endsWith(".jar")) {
			return GhidraBundle.Type.Jar;
		}
		return GhidraBundle.Type.INVALID;
	}

	public Bundle getBundle() {
		return bundleHost.getBundle(getBundleLoc());
	}

	public Bundle install() throws GhidraBundleException {
		return bundleHost.installFromLoc(getBundleLoc());
	}
}
