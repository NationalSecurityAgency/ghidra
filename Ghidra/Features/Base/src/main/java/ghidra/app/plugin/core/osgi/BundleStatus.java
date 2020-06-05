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

import generic.jar.ResourceFile;
import generic.util.Path;

/**
 * The BundleStatus class represents the runtime state and user preferences for OSGi bundles in Ghidra.
 */
public class BundleStatus implements Comparable<BundleStatus> {
	final Path path;
	final GhidraBundle.Type type;
	final String bundleLocation;

	boolean active = false;
	boolean busy = false;

	String summary;

	BundleStatus(ResourceFile path, boolean enabled, boolean readonly, String bundleLoc) {
		this.path = new Path(path, enabled, false, readonly);
		type = GhidraBundle.getType(getPath());
		this.bundleLocation = bundleLoc;
	}

	@Override
	public int compareTo(BundleStatus o) {
		return path.compareTo(o != null ? o.path : null);
	}

	/**
	 * @return true if the bundle is enabled
	 */
	public boolean isEnabled() {
		return path.isEnabled();
	}

	/**
	 * Set the bundle's status to enabled or disabled.
	 * 
	 * @param isEnabled true to set status to enabled
	 */
	public void setEnabled(boolean isEnabled) {
		path.setEnabled(isEnabled);
	}

	/**
	 * @return true if the bundle is read only
	 */
	public boolean isReadOnly() {
		return path.isReadOnly();
	}

	/**
	 * @return the bundle type
	 * 
	 * @see GhidraBundle.Type
	 */
	public GhidraBundle.Type getType() {
		return type;
	}

	/**
	 * @return true if the bundle is active
	 */
	public boolean isActive() {
		return active;
	}

	/**
	 * Set the bundle's status to active or inactive.
	 * 
	 * @param isActive true for active, false for inactive
	 */
	public void setActive(boolean isActive) {
		active = isActive;
	}

	/**
	 * Set the bundle's build summary.
	 * 
	 * @param summary the build summary
	 */
	public void setSummary(String summary) {
		this.summary = summary;
	}

	/**
	 * @return the bundle's build summary
	 */
	public String getSummary() {
		return summary != null ? summary : "";
	}

	/**
	 * @return the bundle's path
	 */
	public ResourceFile getPath() {
		return path.getPath();
	}

	/**
	 * @return true if the bundle's path exists
	 */
	public boolean pathExists() {
		return path.exists();
	}

	/**
	 * @return the bundle's path as a string, using $USER and $GHIDRA_HOME when appropriate 
	 */
	public String getPathAsString() {
		return path.getPathAsString();
	}

	/**
	 * @return the bundle's location identifier
	 */
	public String getBundleLocation() {
		return bundleLocation;
	}

	void setBusy(boolean isBusy) {
		busy = isBusy;
	}

	boolean isBusy() {
		return busy;
	}
}
