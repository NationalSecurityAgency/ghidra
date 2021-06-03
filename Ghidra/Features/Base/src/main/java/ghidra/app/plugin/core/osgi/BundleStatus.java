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
 * The BundleStatus class represents the runtime state and user preferences for bundles.
 */
public class BundleStatus implements Comparable<BundleStatus> {
	private final GhidraBundle.Type type;
	private final String location;

	private final ResourceFile file;
	private final boolean readOnly;
	private boolean enabled;
	private boolean active = false;
	private boolean busy = false;

	private String summary;

	BundleStatus(ResourceFile bundleFile, boolean enabled, boolean readOnly, String bundleLoc) {
		this.file = bundleFile;
		type = GhidraBundle.getType(getFile());
		this.location = bundleLoc;
		this.enabled = enabled;
		this.readOnly = readOnly;
	}

	@Override
	public int compareTo(BundleStatus o) {
		return getPathAsString().compareTo(o.getPathAsString());
	}

	/**
	 * @return true if the bundle is enabled
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * Set the bundle's status to enabled or disabled.
	 * 
	 * @param isEnabled true to set status to enabled
	 */
	public void setEnabled(boolean isEnabled) {
		this.enabled = isEnabled;
	}

	/**
	 * @return true if the bundle is read only
	 */
	public boolean isReadOnly() {
		return readOnly;
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
	 * @return the bundle file
	 */
	public ResourceFile getFile() {
		return file;
	}

	/**
	 * @return true if the bundle file exists
	 */
	public boolean fileExists() {
		return file.exists();
	}

	/**
	 * @return the bundle file path, using $USER and $GHIDRA_HOME when appropriate 
	 */
	public String getPathAsString() {
		return Path.toPathString(file);
	}

	/**
	 * @return the bundle's location identifier
	 */
	public String getLocationIdentifier() {
		return location;
	}

	void setBusy(boolean isBusy) {
		busy = isBusy;
	}

	boolean isBusy() {
		return busy;
	}
}
