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
package ghidra.util.extensions;

import java.net.URL;
import java.net.URLClassLoader;
import java.util.Set;

/**
 * A class loader used with Ghidra extensions.
 */
public class ExtensionModuleClassLoader extends URLClassLoader {

	private ExtensionDetails extensionDir;

	public ExtensionModuleClassLoader(ExtensionDetails extensionDir) {
		// It is important that this class use the default GhidraClassLoader as its parent.  This
		// allows resolution of Ghidra classes from extensions.
		super(getURLs(extensionDir), ExtensionModuleClassLoader.class.getClassLoader());
		this.extensionDir = extensionDir;
	}

	private static URL[] getURLs(ExtensionDetails extensionDir) {
		Set<URL> jars = extensionDir.getLibraries();
		return jars.toArray(URL[]::new);
	}

	@Override
	public String toString() {
		return "Extension ClassLoader for " + extensionDir.getName();
	}
}
