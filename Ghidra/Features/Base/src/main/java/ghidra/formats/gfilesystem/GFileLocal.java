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
package ghidra.formats.gfilesystem;

import java.io.File;

/**
 * {@link GFile} implementation that refers to a real java.io.File on the local
 * file system.
 * <p>
 * This implementation keeps track of the FSRL and GFile path separately so that
 * they can be different, as is the case with LocalFileSystemSub files that
 * have real FSRLs but fake relative paths.
 */
public class GFileLocal implements GFile {

	private GFileSystem fs;
	private FSRL fsrl;
	private String path;
	private File f;
	private GFile parent;

	/**
	 * Create new GFileLocal instance.
	 *
	 * @param f {@link File} on the local filesystem
	 * @param path String path (including filename) of this instance
	 * @param fsrl {@link FSRL} of this instance
	 * @param fs {@link GFileSystem} that created this file.
	 * @param parent Parent directory that contains this file, or null if parent is root.
	 */
	public GFileLocal(File f, String path, FSRL fsrl, GFileSystem fs, GFile parent) {
		this.fs = fs;
		this.fsrl = fsrl;
		this.path = path;
		this.f = f;
		this.parent = parent;
	}

	@Override
	public GFileSystem getFilesystem() {
		return fs;
	}

	@Override
	public FSRL getFSRL() {
		return fsrl;
	}

	@Override
	public GFile getParentFile() {
		return parent;
	}

	@Override
	public String getPath() {
		return path;
	}

	@Override
	public String getName() {
		return fsrl.getName();
	}

	@Override
	public boolean isDirectory() {
		return f.isDirectory();
	}

	@Override
	public long getLength() {
		return f.length();
	}

	@Override
	public long getLastModified() {
		return f.lastModified();
	}

	public File getLocalFile() {
		return f;
	}

	@Override
	public String toString() {
		return "Local " + f.toString() + " with path " + path;
	}

}
