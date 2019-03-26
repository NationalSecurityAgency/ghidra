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
import java.util.ArrayList;
import java.util.List;

//
public class FileResource implements Resource {
	private File file;

	public FileResource(File file) {
		this.file = file;
	}

	@Override
	public Resource getResource(String childPath) {
		return new FileResource(new File(file, childPath));
	}

	@Override
	public String getAbsolutePath() {
		return file.getAbsolutePath();
	}

	@Override
	public ResourceFile[] listFiles() {
		File[] listFiles = file.listFiles();

		if (listFiles == null) {
			return null;
		}

		ResourceFile[] resourceFiles = new ResourceFile[listFiles.length];
		for (int i = 0; i < listFiles.length; i++) {
			resourceFiles[i] = new ResourceFile(new FileResource(listFiles[i]));
		}
		return resourceFiles;
	}

	@Override
	public ResourceFile[] listFiles(ResourceFileFilter filter) {
		File[] listFiles = file.listFiles();
		if (listFiles == null) {
			return null;
		}
		List<ResourceFile> fileList = new ArrayList<>();
		for (File listFile : listFiles) {
			ResourceFile resourceFile = new ResourceFile(new FileResource(listFile));
			if (filter.accept(resourceFile)) {
				fileList.add(resourceFile);
			}
		}
		return fileList.toArray(new ResourceFile[fileList.size()]);
	}

	@Override
	public String getName() {
		return file.getName();
	}

	@Override
	public boolean isDirectory() {
		return file.isDirectory();
	}

	@Override
	public URL toURL() throws MalformedURLException {
		return file.toURI().toURL();
	}

	@Override
	public InputStream getInputStream() throws FileNotFoundException {
		return new FileInputStream(file);
	}

	@Override
	public OutputStream getOutputStream() throws FileNotFoundException {
		return new FileOutputStream(file);
	}

	@Override
	public FileResource getParent() {
		File parent = file.getParentFile();
		if (parent == null) {
			parent = file.getAbsoluteFile().getParentFile();
			if (parent == null) {
				return null;
			}
		}
		return new FileResource(parent);
	}

	@Override
	public long lastModified() {
		return file.lastModified();
	}

	@Override
	public int hashCode() {
		return file.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		return file.equals(((FileResource) obj).file);
	}

	@Override
	public boolean delete() {
		return file.delete();
	}

	@Override
	public boolean exists() {
		return file.exists();
	}

	@Override
	public File getFile() {
		return file;
	}

	@Override
	public File getResourceAsFile(ResourceFile resourceFile) {
		return file;
	}

	@Override
	public long length() {
		return file.length();
	}

	@Override
	public String getCanonicalPath() throws IOException {
		return file.getCanonicalPath();
	}

	@Override
	public boolean isFile() {
		return file.isFile();
	}

	@Override
	public Resource getCanonicalResource() {
		try {
			return new FileResource(file.getCanonicalFile());
		}
		catch (IOException e) {
			return this;
		}
	}

	@Override
	public boolean canWrite() {
		return file.canWrite();
	}

	@Override
	public boolean mkdir() {
		return file.mkdir();
	}

	@Override
	public String toString() {
		return getAbsolutePath();
	}

	@Override
	public File getFileSystemRoot() {
		File testFile = file;
		File parentFile = testFile.getParentFile();
		while (parentFile != null) {
			testFile = parentFile;
			parentFile = testFile.getParentFile();
		}
		return testFile;
	}

	@Override
	public URI toURI() {
		return file.toURI();
	}
}
