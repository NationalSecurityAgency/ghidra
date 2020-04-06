package ghidra.app.plugin.core.osgi;

import java.io.PrintWriter;
import java.util.Collections;
import java.util.List;
import java.util.jar.Manifest;

import org.osgi.framework.Bundle;
import org.osgi.framework.wiring.BundleRequirement;

import aQute.bnd.osgi.Constants;
import aQute.bnd.osgi.Jar;
import generic.jar.ResourceFile;

public class GhidraJarBundle implements GhidraBundle {
	final private BundleHost bundleHost;

	final String bundleLoc;
	final ResourceFile path;

	public GhidraJarBundle(BundleHost bundleHost, ResourceFile path) {
		this.bundleHost = bundleHost;
		this.path = path;
		this.bundleLoc = "file://" + path.getAbsolutePath().toString();
	}

	@Override
	public boolean clean() {
		return false;
	}

	@Override
	public boolean build(PrintWriter writer) throws Exception {
		return true;
	}

	@Override
	public String getBundleLoc() {
		return bundleLoc;
	}

	@Override
	public Bundle getBundle() throws GhidraBundleException {
		return bundleHost.getBundle(getBundleLoc());
	}

	@Override
	public Bundle install() throws GhidraBundleException {
		return bundleHost.installFromLoc(getBundleLoc());
	}

	@Override
	public String getSummary() {
		return null;
	}

	@Override
	public List<BundleRequirement> getAllReqs() {
		Jar jar;
		try {
			jar = new Jar(path.getFile(true));
			Manifest m = jar.getManifest();
			String imps = m.getMainAttributes().getValue(Constants.IMPORT_PACKAGE);
			if (imps != null) {
				return BundleHost.parseImports(imps);
			}
			return Collections.emptyList();
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
