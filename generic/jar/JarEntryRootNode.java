/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package generic.jar;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class JarEntryRootNode extends JarEntryNode {
	private JarFile jarFile;
	private File file;

	public JarEntryRootNode(File file, JarEntryFilter filter) throws IOException {
		super(null, "");
		jarFile = new JarFile(file);
		this.file = file;
		if (filter == null) {
			filter = new DefaultFilter();
		}
		createIndex(filter);
	}

	@Override
	protected JarFile getJarFile() {
		return jarFile;
	}

	protected File getFile() {
		return file;
	}

	public URL toURL() throws MalformedURLException {
		return file.toURI().toURL();
	}

	private void createIndex(JarEntryFilter filter) {
		Enumeration<JarEntry> entries = jarFile.entries();
		while (entries.hasMoreElements()) {
			JarEntry jarEntry = entries.nextElement();
			if (jarEntry.isDirectory()) {
				continue;
			}
			if (filter.accepts(jarEntry)) {
				addFile(jarEntry.getName());
			}
		}

	}

	private void addFile(String path) {
		String[] split = path.split("/");
		JarEntryNode node = this;
		for (String string : split) {
			node = getOrCreateNode(node, string);
		}
	}

	private JarEntryNode getOrCreateNode(JarEntryNode node, String name) {
		return node.createNode(name);  // if already exists, create will return exiting node
	}

	private static class DefaultFilter implements JarEntryFilter {

		@Override
		public boolean accepts(JarEntry jarEntry) {
			String name = jarEntry.getName();
			if (name.endsWith(".class")) {
				return false;
			}
			if (name.endsWith(".png")) {
				return false;
			}
			if (name.endsWith(".gif")) {
				return false;
			}
			return true;
		}

	}
}
