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
package ghidra;

import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.ApplicationProperties;
import ghidra.framework.GModule;
import utility.application.ApplicationLayout;
import utility.module.ModuleUtilities;

/**
 * The Ghidra jar application layout defines the customizable elements of the Ghidra application's 
 * directory structure when running in "single jar mode."
 */
public class GhidraJarApplicationLayout extends GhidraApplicationLayout {

	/**
	 * Constructs a new Ghidra jar application layout object.
	 * 
	 * @throws FileNotFoundException if there was a problem getting a user directory.
	 * @throws IOException if there was a problem getting the application properties or modules.
	 */
	public GhidraJarApplicationLayout() throws FileNotFoundException, IOException {
		super();
	}

	@Override
	public boolean inSingleJarMode() {
		return true;
	}

	@Override
	protected Collection<ResourceFile> findGhidraApplicationRootDirs() {
		List<ResourceFile> dirs = new ArrayList<>();
		String appPropPath = "/_Root/Ghidra/" + ApplicationProperties.PROPERTY_FILE;
		URL appPropUrl = ApplicationLayout.class.getResource(appPropPath);
		ResourceFile rootDir = fromUrl(appPropUrl).getParentFile();
		dirs.add(rootDir);
		return dirs;
	}

	@Override
	protected ResourceFile findGhidraApplicationInstallationDir() {
		if (getApplicationRootDirs().isEmpty()) {
			return null;
		}
		return getApplicationRootDirs().iterator().next().getParentFile();
	}

	@Override
	protected Map<String, GModule> findGhidraModules() throws IOException {
		return ModuleUtilities.findModules(getApplicationRootDirs(),
			ModuleUtilities.findJarModuleRootDirectories(getApplicationRootDirs().iterator().next(),
				new ArrayList<>()));
	}

	@Override
	protected ResourceFile findExtensionArchiveDirectory() {
		return null;
	}

	@Override
	protected List<ResourceFile> findExtensionInstallationDirectories() {
		URL extensionInstallUrl = ApplicationLayout.class.getResource("/_Root/Ghidra/Extensions");
		ResourceFile extensionInstallDir = fromUrl(extensionInstallUrl);
		return Collections.singletonList(extensionInstallDir);
	}

	/**
	 * Gets a {@link ResourceFile} from a {@link URL}
	 * 
	 * @param url The {@link URL}
	 * @return A {@link ResourceFile} from the given {@link URL}
	 */
	private ResourceFile fromUrl(URL url) {
		String urlString = url.toExternalForm();
		try {
			// Decode the URL to replace things like %20 with real spaces.
			// Note: can't use URLDecoder.decode(String, Charset) because Utility must be 
			// Java 1.8 compatible.
			urlString = URLDecoder.decode(urlString, "UTF-8");
		}
		catch (UnsupportedEncodingException e) {
			// Shouldn't happen, but failed to find UTF-8 encoding.
			// Proceed without decoding, and hope for the best.
		}
		return new ResourceFile(urlString);
	}
}
