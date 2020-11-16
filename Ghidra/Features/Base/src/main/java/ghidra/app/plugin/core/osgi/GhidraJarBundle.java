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
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.stream.Collectors;

import org.apache.felix.framework.util.manifestparser.ManifestParser;
import org.osgi.framework.BundleException;
import org.osgi.framework.wiring.BundleCapability;
import org.osgi.framework.wiring.BundleRequirement;

import aQute.bnd.osgi.Jar;
import generic.jar.ResourceFile;
import ghidra.util.exception.AssertException;

/**
 * Proxy to an ordinary OSGi Jar bundle.  {@link GhidraJarBundle#build(PrintWriter)} does nothing.   
 */
public class GhidraJarBundle extends GhidraBundle {
	final String bundleLocation;

	/**
	 * {@link GhidraJarBundle} wraps an ordinary OSGi bundle .jar.
	 * 
	 * @param bundleHost the {@link BundleHost} instance this bundle will belong to
	 * @param file the jar file
	 * @param enabled true to start enabled
	 * @param systemBundle true if this is a Ghidra system bundle
	 */
	public GhidraJarBundle(BundleHost bundleHost, ResourceFile file, boolean enabled,
			boolean systemBundle) {
		super(bundleHost, file, enabled, systemBundle);
		this.bundleLocation = "file://" + file.getAbsolutePath().toString();
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
	public String getLocationIdentifier() {
		return bundleLocation;
	}

	protected ManifestParser createManifestParser() throws GhidraBundleException {
		try (Jar jar = new Jar(file.getFile(true))) {
			Manifest manifest = jar.getManifest();
			if (manifest == null) {
				throw new GhidraBundleException(bundleLocation, "jar bundle with no manifest");
			}
			Attributes mainAttributes = manifest.getMainAttributes();
			Map<String, Object> headerMap = mainAttributes.entrySet()
					.stream()
					.collect(
						Collectors.toMap(e -> e.getKey().toString(), e -> e.getValue().toString()));
			return new ManifestParser(null, null, null, headerMap);
		}
		catch (BundleException e) {
			throw new GhidraBundleException(bundleLocation, "parsing manifest", e);
		}
		catch (GhidraBundleException e) {
			throw e;
		}
		catch (Exception e) {
			throw new AssertException("Unexpected exception while parsing manifest", e);
		}
	}

	@Override
	public List<BundleRequirement> getAllRequirements() throws GhidraBundleException {
		ManifestParser manifestParser = createManifestParser();
		return manifestParser.getRequirements();
	}

	@Override
	public List<BundleCapability> getAllCapabilities() throws GhidraBundleException {
		ManifestParser manifestParser = createManifestParser();
		return manifestParser.getCapabilities();
	}

}
