package ghidra.app.script.osgi;

import org.osgi.framework.Bundle;
import org.osgi.framework.BundleException;

public class GhidraBundleException extends OSGiException {
	private Bundle bundle;
	private String bundle_loc;

	public GhidraBundleException(Bundle bundle, String msg, Throwable cause) {
		super(msg, cause);
		this.bundle = bundle;
	}

	public GhidraBundleException(Bundle bundle, String msg) {
		super(msg);
		this.bundle = bundle;
	}

	public GhidraBundleException(String bundle_loc, String msg, BundleException cause) {
		super(msg, cause);
		this.bundle_loc = bundle_loc;
	}

	public Bundle getBundle() {
		return bundle;
	}

	public String getBundleLocation() {
		return bundle_loc;
	}

}
