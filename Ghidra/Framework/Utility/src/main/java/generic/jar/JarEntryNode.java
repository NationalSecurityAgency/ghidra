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

import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class JarEntryNode {
	private final JarEntryNode parent;
	private final String name;
	private Map<String, JarEntryNode> childMap;

	JarEntryNode(JarEntryNode parent, String name) {
		this.name = name;
		this.parent = parent;
	}

	public JarEntryNode getNode(String childName) {
		if (childMap == null) {
			return null;
		}
		if (childName.equals(".")) {
			return this;
		}
		if (childName.equals("..")) {
			return parent;
		}
		return childMap.get(childName);
	}

	JarEntryNode createNode(String childName) {
		JarEntryNode file = getNode(childName);
		if (file == null) {
			file = new JarEntryNode(this, childName);
			if (childMap == null) {
				childMap = new HashMap<String, JarEntryNode>();
			}
			childMap.put(childName, file);
		}
		return file;
	}

	String getPath() {
		if (parent == null) {
			return "";
		}
		String parentPath = parent.getPath();
		return parentPath.length() == 0 ? name : parentPath + "/" + name;
	}

	public List<JarEntryNode> getChildren() {
		if (childMap == null) {
			return null;
		}
		return new ArrayList<JarEntryNode>(childMap.values());
	}

	public String getName() {
		return name;
	}

	public boolean isDirectory() {
		return childMap != null;
	}

	public boolean isFile() {
		return childMap == null;
	}

	public InputStream getInputStream() throws IOException {
		JarFile jarFile = getJarFile();
		JarEntry jarEntry = jarFile.getJarEntry(getPath());
		return jarFile.getInputStream(jarEntry);
	}

	protected JarFile getJarFile() {
		return parent.getJarFile();
	}

	public JarEntryNode getParent() {
		return parent;
	}

	public long lastModified() {
		JarFile jarFile = getJarFile();
		JarEntry jarEntry = jarFile.getJarEntry(getPath());
		return jarEntry.getTime();
	}

	public JarEntryNode getNode(String[] path) {
		JarEntryNode temp = this;
		for (String childName : path) {
			temp = temp.getNode(childName);
			if (temp == null) {
				return null;
			}
		}
		return temp;
	}

	public long length() {
		JarFile jarFile = getJarFile();
		JarEntry jarEntry = jarFile.getJarEntry(getPath());
		return jarEntry.getSize();
	}

}
