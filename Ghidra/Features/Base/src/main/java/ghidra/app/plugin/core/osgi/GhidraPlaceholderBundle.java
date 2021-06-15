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

import java.io.PrintWriter;
import java.util.Collections;
import java.util.List;

import org.osgi.framework.wiring.BundleCapability;
import org.osgi.framework.wiring.BundleRequirement;

import generic.jar.ResourceFile;

/**
 * {@link GhidraPlaceholderBundle} represents invalid bundle paths in the GUI.
 */
public class GhidraPlaceholderBundle extends GhidraBundle {
	final String summary;

	GhidraPlaceholderBundle(BundleHost bundleHost, ResourceFile bundleFile, boolean isEnabled,
			boolean isSystemBundle, String summary) {
		super(bundleHost, bundleFile, isEnabled, isSystemBundle);
		this.summary = summary;
	}

	/**
	 * @return a summary of the reason for this placeholder
	 */
	String getSummary() {
		return summary;
	}

	@Override
	boolean clean() {
		return false;
	}

	@Override
	public boolean build(PrintWriter writer) throws Exception {
		return false;
	}

	@Override
	public String getLocationIdentifier() {
		return "invalid://" + getFile();
	}

	@Override
	public List<BundleRequirement> getAllRequirements() throws GhidraBundleException {
		return Collections.emptyList();
	}

	@Override
	public List<BundleCapability> getAllCapabilities() throws GhidraBundleException {
		return Collections.emptyList();
	}

	@Override
	public boolean isEnabled() {
		return false;
	}

	@Override
	public boolean isActive() {
		return false;
	}

}
