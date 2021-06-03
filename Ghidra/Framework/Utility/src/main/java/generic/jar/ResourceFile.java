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

import java.io.*;
import java.net.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Class for representing file object regardless of whether they are actual files in the file system or
 * or files stored inside of a jar file.  This class provides most all the same capabilities as the
 * File class.
 *
 */

public class ResourceFile implements Comparable<ResourceFile> {
	private static final String JAR_FILE_PREFIX = "jar:file:";
	private Resource resource;
	private static Map<String, JarResource> jarRootsMap = new HashMap<String, JarResource>();

	/**
	 * Construct a ResourceFile that represents a normal file in the file system.
	 * @param file the file in the file system.
	 */
	public ResourceFile(File file) {
		resource = new FileResource(file);
	}

	/**
	 * Construct a new ResourceFile from a parent file and a relative child path.
	 * @param resourceFile the parent file
	 * @param path the child path.
	 */
	public ResourceFile(ResourceFile resourceFile, String path) {
		if (resourceFile == null) {
			throw new IllegalArgumentException("Parent ResourceFile cannot be null.");
		}

		resource = resourceFile.resource.getResource(path);
	}

	ResourceFile(Resource resource) {
		this.resource = resource;
	}

	/**
	 * Constructs a Resource file from string path that can be either a file path or a jar url.
	 * @param absolutePath the path to the file.
	 */
	public ResourceFile(String absolutePath) {
		this(absolutePath, null);
	}

	/**
	 * Constructs a Resource file from string path that can be either a file path or a jar url.
	 * 
	 * @param absolutePath the path to the file.
	 * @param filter The filter used to exclude files from being loaded
	 */
	public ResourceFile(String absolutePath, JarEntryFilter filter) {
		if (absolutePath.startsWith(JAR_FILE_PREFIX)) {
			int indexOf = absolutePath.indexOf("!/");
			if (indexOf < 0) {
				throw new IllegalArgumentException("Invalid jar specification: " + absolutePath);
			}
			String filePath = absolutePath.substring(JAR_FILE_PREFIX.length(), indexOf);
			String relativePath = absolutePath.substring(indexOf + 2);
			Resource root = jarRootsMap.get(filePath);
			try {
				if (root == null) {
					root = openJarResourceFile(new File(filePath), filter).resource;
				}
				resource = root.getResource(relativePath);
				return;
			}
			catch (IOException e) {
				throw new IllegalArgumentException("Failed to open jar: " + filePath, e);
			}
		}
		resource = new FileResource(new File(absolutePath));
	}

	/**
	 * Creates a new Root ResourceFile for a given jar file.
	 * @param jarFile the jar file to open.
	 * @param filter JarEntryFilter that will filter out unwanted jar entries.
	 * @return A Resource file that represents the root of the jarfile file system.
	 * @throws IOException if the jar file can't be read.
	 */
	public static ResourceFile openJarResourceFile(File jarFile, JarEntryFilter filter)
			throws IOException {

		JarResource root = new JarResource(jarFile, filter);
		ResourceFile rootResourceFile = new ResourceFile(root);
		jarRootsMap.put(jarFile.getCanonicalPath(), root);
		return rootResourceFile;
	}

	/**
	 * Returns the absolute file path for this file. 
	 * @return the absolute file path for this file.
	 */
	public String getAbsolutePath() {
		return resource.getAbsolutePath();
	}

	/**
	 * Returns the canonical file path for this file.
	 * @return the absolute file path for this file.
	 */
	public String getCanonicalPath() throws IOException {
		return resource.getCanonicalPath();
	}

	/**
	 * Returns a array of ResourceFiles if this ResourceFile is a directory. Otherwise return null.
	 * @return  the child ResourceFiles if this is a directory, null otherwise.
	 */
	public ResourceFile[] listFiles() {
		return resource.listFiles();
	}

	/**
	 * Returns a array of ResourceFiles if this ResourceFile is a directory. Otherwise return null.
	 * @param filter a filter to restrict the array of files returned.
	 * @return  the child ResourceFiles if this is a directory, null otherwise.
	 */
	public ResourceFile[] listFiles(ResourceFileFilter filter) {
		return resource.listFiles(filter);
	}

	/**
	 * Returns the simple name of the file.
	 * @return the simple name of the file.
	 */
	public String getName() {
		return resource.getName();
	}

	/**
	 * Returns true if this Resource file exists and is a directory.
	 * @return true if this Resource file exists and is a directory.
	 */
	public boolean isDirectory() {
		return resource.isDirectory();
	}

	/**
	 * Returns the parent of this ResourceFile or null if it is a root.
	 * @return the parent of this ResourceFile or null if it is a root.
	 */
	public ResourceFile getParentFile() {
		Resource parent = resource.getParent();
		return parent == null ? null : new ResourceFile(parent);
	}

	/**
	 * Returns a URL that represents this file object.
	 * @return a URL that represents this file object.
	 * @throws MalformedURLException if a URL can't be formed for this file.
	 */
	public URL toURL() throws MalformedURLException {
		return resource.toURL();
	}

	/**
	 * Returns the time that this file was last modified.
	 * @return the time that this file was last modified.
	 */
	public long lastModified() {
		return resource.lastModified();
	}

	/**
	 * If this file exists and is not a directory, it will return an InputStream for the file's 
	 * contents. 
	 * @return an InputStream for the file's contents.
	 * @throws FileNotFoundException if the file does not exist.
	 * @throws IOException 
	 */
	public InputStream getInputStream() throws FileNotFoundException, IOException {
		return resource.getInputStream();
	}

	/**
	 * Attempts to delete the file.  Not supported (returns false) for files within a jar file.
	 * @return true if the file was deleted, false otherwise.
	 */
	public boolean delete() {
		return resource.delete();
	}

	/**
	 * Returns true if the file exists.
	 * @return true if the file exists.
	 */
	public boolean exists() {
		return resource.exists();
	}

	/**
	 * Returns an OutputStream if the file can be opened for writing.
	 * @return an OutputStream if the file can be opened for writing.
	 * @throws FileNotFoundException if the file can't be created or opened for writing.
	 */
	public OutputStream getOutputStream() throws FileNotFoundException {
		return resource.getOutputStream();
	}

	/**
	 * Returns a File object.  If this ResourceFile represents a standard filesystem, then no
	 * copy is necessary to return a file.  If this ResourceFile represents a compressed 
	 * filesystem, then a copy from that filesystem to the real filesystem is needed to create
	 * a File object.  <code>copyIfNeeded</code> allows you to dictate whether a copy should take 
	 * place, if needed.
	 * <p>
	 * If you just want the contents of a file, then call {@link #getInputStream()}.
	 * 
	 * @param  copyIfNeeded true to copy the file when embedded in a compressed filesystem; false
	 *                      to return null in that case.
	 * @return a File object or null if not a file and copyIfNeeded was false
	 */
	public File getFile(boolean copyIfNeeded) {
		if (copyIfNeeded) {
			return resource.getResourceAsFile(this);
		}
		return resource.getFile(); // will be null if the resource is a compressed filesystem
	}

	/**
	 * Returns the size of this file.
	 * @return the size of the file.
	 */
	public long length() {
		return resource.length();
	}

	/**
	 * Returns true if this file exists and is not a directory.
	 * @return  true if this file exists and is not a directory.
	 */
	public boolean isFile() {
		return resource.isFile();
	}

	/**
	 * Returns the canonicalFile for this file.
	 * @return the canonicalFile for this file.
	 */
	public ResourceFile getCanonicalFile() {
		Resource newResource = resource.getCanonicalResource();
		if (resource == newResource) {
			return this;
		}
		return new ResourceFile(newResource);
	}

	/**
	 * Returns true if this file can be written to.
	 * @return  true if this file can be written to.
	 */
	public boolean canWrite() {
		return resource.canWrite();
	}

	/**
	 * Creates a directory for the path represented by this file.
	 * @return true if a new directory was created.
	 */
	public boolean mkdir() {
		return resource.mkdir();
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
		return resource.equals(((ResourceFile) obj).resource);
	}

	@Override
	public int hashCode() {
		return resource.hashCode();
	}

	@Override
	public int compareTo(ResourceFile o) {
		return getAbsolutePath().compareTo(o.getAbsolutePath());
	}

	@Override
	public String toString() {
		return getAbsolutePath();
	}

	/**
	 * Returns the root file for this file.
	 * @return the root file for this file.
	 */
	public File getFileSystemRoot() {
		return resource.getFileSystemRoot();
	}

	/**
	 * Returns a URI for this file object.
	 * @return a URI for this file object.
	 */
	public URI toURI() {
		return resource.toURI();
	}
}
