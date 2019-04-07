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
package generic.jar;

import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.List;

import utilities.util.FileUtilities;
import utility.application.ApplicationSettings;

public class JarResource implements Resource {
	private final JarEntryRootNode root;
	private final JarEntryNode node;
	private final String name;
	private final String path;

	public JarResource(File jarFile, JarEntryFilter filter) throws IOException {
		root = new JarEntryRootNode(jarFile, filter);
		node = root;
		name = root.getName();
		path = root.getPath();
	}

	public JarResource(JarResource parent, String path) {
		this.root = parent.root;
		String myName;
		JarEntryNode myNode;
		String myPath;
		path = path.replace('\\', '/');
		if (path.startsWith("/")) {
			path = path.substring(1);
		}
		if (path.length() == 0) {
			myName = parent.getName();
			myNode = parent.node;
			myPath = parent.path;
		}
		else {
			String[] split = path.split("/");
			myName = split[split.length - 1];
			myNode = parent.node == null ? null : parent.node.getNode(split);
			myPath = myNode != null ? myNode.getPath() : parent.path + "/" + path;
		}
		this.name = myName;
		this.node = myNode;
		this.path = myPath;
	}

	JarResource(JarEntryRootNode root, JarEntryNode node) {
		this.root = root;
		this.node = node;
		this.name = node.getName();
		this.path = node.getPath();
	}

	@Override
	public String getAbsolutePath() {
		String jarPath;
		try {
			jarPath = root.toURL().toExternalForm();
		}
		catch (IOException e) {
			jarPath = "file:" + root.getFile().getAbsolutePath();
		}
		return "jar:" + jarPath + "!/" + path;
	}

	@Override
	public URL toURL() throws MalformedURLException {
		return new URL(getAbsolutePath());
	}

	@Override
	public URI toURI() {
		try {
			return new URI(getAbsolutePath());
		}
		catch (URISyntaxException e) {
			throw new AssertException("Unexpected exception getting URI: " + this);
		}
	}

	@Override
	public ResourceFile[] listFiles() {
		if (!isDirectory()) {
			return null;
		}
		List<JarEntryNode> children = node.getChildren();
		ResourceFile[] files = new ResourceFile[children.size()];
		for (int i = 0; i < files.length; i++) {
			files[i] = new ResourceFile(new JarResource(root, children.get(i)));
		}
		return files;
	}

	@Override
	public ResourceFile[] listFiles(ResourceFileFilter filter) {
		if (!isDirectory()) {
			return null;
		}
		List<ResourceFile> fileList = new ArrayList<ResourceFile>();
		List<JarEntryNode> children = node.getChildren();
		for (JarEntryNode jarEntryNode : children) {
			ResourceFile file = new ResourceFile(new JarResource(root, jarEntryNode));
			if (filter.accept(file)) {
				fileList.add(file);
			}
		}
		return fileList.toArray(new ResourceFile[fileList.size()]);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public boolean isDirectory() {
		return node == null ? false : node.isDirectory();
	}

	@Override
	public boolean isFile() {
		return node == null ? false : node.isFile();
	}

	@Override
	public InputStream getInputStream() throws IOException {
		if (node == null || isDirectory()) {
			throw new FileNotFoundException(path + " does not exist or is a directory");
		}
		return node.getInputStream();
	}

	@Override
	public Resource getParent() {
		if (node != null) {
			if (node == root) {
				return null;
			}
			return new JarResource(root, node.getParent());
		}
		JarResource rootResource = new JarResource(root, root);
		String parentPath = getParentPath();
		if (parentPath == null) {
			return rootResource;
		}
		return new JarResource(rootResource, parentPath);
	}

	private String getParentPath() {
		String[] split = path.split("/");
		if (split.length == 1) {
			return null;
		}
		StringBuffer buf = new StringBuffer();
		buf.append(split[0]);
		for (int i = 1; i < split.length; i++) {
			buf.append("/");
			buf.append(split[i]);
		}
		return buf.toString();
	}

	@Override
	public long lastModified() {
		if (node != null) {
			return node.lastModified();
		}
		return 0;
	}

	@Override
	public boolean delete() {
		return false;
	}

	@Override
	public boolean exists() {
		return node != null;
	}

	@Override
	public OutputStream getOutputStream() throws FileNotFoundException {
		throw new FileNotFoundException("Cannot write to a file inside of a jar file!");
	}

	@Override
	public Resource getResource(String childPath) {
		if (childPath == null || childPath.length() == 0) {
			return this;
		}
		return new JarResource(this, childPath);
	}

	@Override
	public File getFile() {
		return null;
	}

	@Override
	public File getResourceAsFile(ResourceFile resourceFile) {
		File userCopyDir = getFileCacheDirectory();
		if (!userCopyDir.exists()) {
			FileUtilities.mkdirs(userCopyDir);
		}

		File fileCopy = new File(userCopyDir, name);
		if (!fileCopy.exists()) {
			try {
				FileUtilities.copyFile(resourceFile, fileCopy, false, null);
				fileCopy.setExecutable(true);
			}
			catch (IOException e) {
				Msg.error(this, "Resource file copy failed:  " + resourceFile, e);
			}
		}
		return fileCopy;
	}

	private File getFileCacheDirectory() {

		File settingsDir = ApplicationSettings.getUserApplicationSettingsDirectory();
		return new File(settingsDir, "jar.resource.copied.files");
	}

	@Override
	public long length() {
		return node.length();
	}

	@Override
	public String getCanonicalPath() throws IOException {
		return getAbsolutePath();
	}

	@Override
	public Resource getCanonicalResource() {
		return this;
	}

	@Override
	public boolean canWrite() {
		return false;
	}

	@Override
	public boolean mkdir() {
		return false;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (obj.getClass() != getClass()) {
			return false;
		}
		JarResource other = (JarResource) obj;
		return root == other.root && name.equals(other.name) && path.equals(other.path);
	}

	@Override
	public int hashCode() {
		return path.hashCode();
	}

	@Override
	public String toString() {
		return getAbsolutePath();
	}

	@Override
	public File getFileSystemRoot() {
		return root.getFile();
	}

}
