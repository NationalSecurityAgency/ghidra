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
import org.osgi.framework.wiring.BundleCapability;
import org.osgi.framework.wiring.BundleRequirement;

import generic.jar.ResourceFile;

/**
 * Proxy for an OSGi bundle that may require being built.
 */
public abstract class GhidraBundle {

	protected final ResourceFile file;

	protected final BundleHost bundleHost;
	protected boolean enabled;
	protected boolean systemBundle;

	GhidraBundle(BundleHost bundleHost, ResourceFile bundleFile, boolean enabled,
			boolean systemBundle) {
		this.bundleHost = bundleHost;
		this.file = bundleFile;
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
	 * same as {@link #build(PrintWriter)} with writer = {@link System#err}.
	 * 
	 * @return true if build happened, false if already built
	 * @throws Exception if the build cannot complete
	 */
	public boolean build() throws Exception {
		return build(new PrintWriter(System.err));
	}

	/**
	 * Return the location identifier of the bundle that this GhidraBundle represents.
	 * 
	 * <p>The location identifier is used by the framework, e.g. it is passed to
	 * {@link org.osgi.framework.BundleContext#installBundle} when the bundle is 
	 * first installed.
	 * 
	 * <p>Although the bundle location is a URI, outside of interactions with the framework,
	 * the bundle location should remain opaque.
	 * 
	 * @return location identifier of this bundle 
	 */
	public abstract String getLocationIdentifier();

	public abstract List<BundleRequirement> getAllRequirements() throws GhidraBundleException;

	public abstract List<BundleCapability> getAllCapabilities() throws GhidraBundleException;

	/**
	 * @return the file where this bundle is loaded from
	 */
	public ResourceFile getFile() {
		return file;
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
	 * <p>If a bundle is enabled its contents will be scanned, e.g. for scripts.
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
	 * Get the type of a GhidraBundle from its file.
	 * 
	 * @param file a bundle file
	 * @return the type
	 */
	static GhidraBundle.Type getType(ResourceFile file) {
		if (file.isDirectory()) {
			return GhidraBundle.Type.SOURCE_DIR;
		}
		String fileName = file.getName().toLowerCase();
		if (fileName.endsWith(".bnd")) {
			return GhidraBundle.Type.BND_SCRIPT;
		}
		if (fileName.endsWith(".jar")) {
			return GhidraBundle.Type.JAR;
		}
		return GhidraBundle.Type.INVALID;
	}

	/**
	 * Get the type of a GhidraBundle from its file.
	 * 
	 * @param file a bundle file
	 * @return the type
	 */
	public static GhidraBundle.Type getType(File file) {
		if (file.isDirectory()) {
			return GhidraBundle.Type.SOURCE_DIR;
		}
		String fileName = file.getName().toLowerCase();
		if (fileName.endsWith(".bnd")) {
			return GhidraBundle.Type.BND_SCRIPT;
		}
		if (fileName.endsWith(".jar")) {
			return GhidraBundle.Type.JAR;
		}
		return GhidraBundle.Type.INVALID;
	}

	/**
	 * Get the OSGi bundle represented by this GhidraBundle or null if it isn't in
	 * the "installed" state.
	 * 
	 * @return a Bundle or null
	 */
	public Bundle getOSGiBundle() {
		return bundleHost.getOSGiBundle(getLocationIdentifier());
	}

	/**
	 * @return true if this bundle is active
	 */
	public boolean isActive() {
		Bundle bundle = getOSGiBundle();
		return (bundle != null) && bundle.getState() == Bundle.ACTIVE;
	}

	/**
	 * A GhidraBundle can be
	 * <ul>
	 * <li>a Bndtools .bnd script</li>
	 * <li>an OSGi bundle .jar file</li>
	 * <li>a directory of Java source</li>
	 * </ul>
	 *  
	 */
	enum Type {
		BND_SCRIPT, JAR, SOURCE_DIR, INVALID
	}

}
