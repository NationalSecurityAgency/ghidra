/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.osgi;

import java.io.File;
import java.io.PrintWriter;
import java.util.List;

import org.osgi.framework.Bundle;
import org.osgi.framework.wiring.BundleRequirement;

import generic.jar.ResourceFile;

/**
 * Proxy for an OSGi bundle that may require being built.
 */
public abstract class GhidraBundle {

	protected final ResourceFile path;
	protected final BundleHost bundleHost;
	protected boolean enabled;
	protected boolean systemBundle;

	GhidraBundle(BundleHost bundleHost, ResourceFile bundlePath, boolean enabled,
			boolean systemBundle) {
		this.bundleHost = bundleHost;
		this.path = bundlePath;
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
	 * @param writer console for build messages to user 
	 * @return true if build happened, false if already built
	 * @throws Exception if the build cannot complete
	 */
	public abstract boolean build(PrintWriter writer) throws Exception;

	/**
	 * same as {@link #build(PrintWriter)} with writer = {@link System.err}.
	 */
	@SuppressWarnings("javadoc")
	public boolean build() throws Exception {
		return build(new PrintWriter(System.err));
	}

	/**
	 * Return the location identifier of the bundle that this GhidraBundle represents.
	 * The location identifier is passed to {@link org.osgi.framework.BundleContext#installBundle} when this
	 * bundle is installed.
	 * 
	 * @return location identifier of this bundle 
	 */
	public abstract String getBundleLocation();

	abstract List<BundleRequirement> getAllRequirements();

	/**
	 * @return this bundle's path
	 */
	public ResourceFile getPath() {
		return path;
	}

	/**
	 * @return true if this bundle is enabled
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * set the enablement flag for this bundle.
	 * 
	 * If a bundle is enabled its contents will be scanned, e.g. for scripts.
	 * 
	 * @param enabled new state
	 */
	void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	/**
	 * If a bundle is a "system bundle" it cannot be removed and its contends cannot be edited.
	 * 
	 * @return true if this is a system bundle
	 */
	public boolean isSystemBundle() {
		return systemBundle;
	}

	/**
	 * A GhidraBundle can be
	 * <ul>
	 * <li>a Bndtools .bnd script</li>
	 * <li>an OSGi bundle .jar file</li>
	 * <li>a directory of Java source</li>
	 * </u>
	 *  
	 */
	enum Type {
		BndScript, Jar, SourceDir, INVALID
	}

	/**
	 * a string error with a time stamp
	 */
	public static class BuildFailure {
		long when = -1;
		StringBuilder message = new StringBuilder();
	}

	/**
	 * Get the type of a GhidraBundle from its path.
	 * 
	 * @param path a resource path
	 * @return the type
	 */
	static GhidraBundle.Type getType(ResourceFile path) {
		if (path.isDirectory()) {
			return GhidraBundle.Type.SourceDir;
		}
		String n = path.getName().toLowerCase();
		if (n.endsWith(".bnd")) {
			return GhidraBundle.Type.BndScript;
		}
		if (n.endsWith(".jar")) {
			return GhidraBundle.Type.Jar;
		}
		return GhidraBundle.Type.INVALID;
	}

	/**
	 * Get the type of a GhidraBundle from its path.
	 * 
	 * @param path a file system path
	 * @return the type
	 */
	public static GhidraBundle.Type getType(File path) {
		if (path.isDirectory()) {
			return GhidraBundle.Type.SourceDir;
		}
		String n = path.getName().toLowerCase();
		if (n.endsWith(".bnd")) {
			return GhidraBundle.Type.BndScript;
		}
		if (n.endsWith(".jar")) {
			return GhidraBundle.Type.Jar;
		}
		return GhidraBundle.Type.INVALID;
	}

	/**
	 * Get the OSGi bundle respresented by this GhidraBundle or null
	 * 
	 * @return a Bundle or null
	 */
	public Bundle getOSGiBundle() {
		return bundleHost.getOSGiBundle(getBundleLocation());
	}

	/**
	 * @return true if this bundle is active
	 */
	public boolean isActive() {
		Bundle b = getOSGiBundle();
		return (b != null) && b.getState() == Bundle.ACTIVE;
	}

}
