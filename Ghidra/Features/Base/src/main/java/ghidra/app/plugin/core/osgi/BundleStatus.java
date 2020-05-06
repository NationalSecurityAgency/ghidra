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
 * 
 * XXX: this class relies on generic.util.Path solely for the parsing and formatting of USER_HOME and GHIDRA_HOME
 */
public class BundleStatus implements Comparable<BundleStatus> {
	final Path path;
	final GhidraBundle.Type type;

	boolean active = false;
	boolean busy = false;

	public boolean isEnabled() {
		return path.isEnabled();
	}

	public void setEnabled(boolean isEnabled) {
		path.setEnabled(isEnabled);
	}

	public boolean isReadOnly() {
		return path.isReadOnly();
	}

	String summary;

	public GhidraBundle.Type getType() {
		return type;
	}

	BundleStatus(String path, boolean enabled, boolean readonly) {
		this.path = new Path(path, enabled, false, readonly);
		type = GhidraBundle.getType(getPath());
	}

	BundleStatus(ResourceFile path, boolean enabled, boolean readonly) {
		this.path = new Path(path, enabled, false, readonly);
		type = GhidraBundle.getType(getPath());
	}

	public boolean isDirectory() {
		return getPath().isDirectory();
	}

	public boolean isActive() {
		return active;
	}

	public void setActive(boolean b) {
		active = b;
	}

	public void setBusy(boolean b) {
		busy = b;
	}

	public boolean isBusy() {
		return busy;
	}

	public void setSummary(String summary) {
		this.summary = summary;
	}

	public String getSummary() {
		return summary != null ? summary : "";
	}

	public ResourceFile getPath() {
		return path.getPath();
	}

	public boolean pathExists() {
		return path.exists();
	}

	@Override
	public int compareTo(BundleStatus o) {
		return path.compareTo(o != null ? o.path : null);
	}

	public String getPathAsString() {
		return path.getPathAsString();
	}

}
