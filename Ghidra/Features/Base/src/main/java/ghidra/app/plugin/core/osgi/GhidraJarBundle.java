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
import java.util.jar.Manifest;

import org.osgi.framework.wiring.BundleRequirement;

import aQute.bnd.osgi.Constants;
import aQute.bnd.osgi.Jar;
import generic.jar.ResourceFile;

public class GhidraJarBundle extends GhidraBundle {
	final String bundleLoc;

	public GhidraJarBundle(BundleHost bundleHost, ResourceFile path, boolean enabled,
			boolean systemBundle) {
		super(bundleHost, path, enabled, systemBundle);
		this.bundleLoc = "file://" + path.getAbsolutePath().toString();
	}

	@Override
	public boolean clean() {
		return false;
	}

	@Override
	public boolean build(PrintWriter writer) throws Exception {
		return false;
	}

	@Override
	public String getBundleLoc() {
		return bundleLoc;
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
