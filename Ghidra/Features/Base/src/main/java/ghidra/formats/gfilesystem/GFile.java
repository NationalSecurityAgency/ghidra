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

import java.io.IOException;
import java.util.List;

/**
 * Represents a file in a {@link GFileSystem filesystem}.
 * <p>
 * Only valid while the {@link #getFilesystem() owning filesystem} object is still open and not
 * {@link GFileSystem#close() closed}.
 * <p>
 */
public interface GFile {

	/**
	 * The {@link GFileSystem} that owns this file.
	 * @return {@link GFileSystem} that owns this file.
	 */
	public GFileSystem getFilesystem();

	/**
	 * The {@link FSRL} of this file.
	 *
	 * @return {@link FSRL} of this file.
	 */
	public FSRL getFSRL();

	/**
	 * The parent directory of this file.
	 *
	 * @return parent {@link GFile} directory of this file.
	 */
	public GFile getParentFile();

	/**
	 * The path and filename of this file, relative to its owning filesystem.
	 *
	 * @return path and filename of this file, relative to its owning filesystem.
	 */
	public String getPath();

	/**
	 * The name of this file.
	 *
	 * @return name of this file.
	 */
	public String getName();

	/**
	 * Returns true if this is a directory.
	 * <p>
	 * @return boolean true if this file is a directory, false otherwise.
	 */
	public boolean isDirectory();

	/**
	 * Returns the length of this file, or -1 if not known.
	 *
	 * @return number of bytes in this file.
	 */
	public long getLength();

	default public long getLastModified() {
		return -1;
	}

	/**
	 * Returns a listing of files in this sub-directory.
	 * <p>
	 * @return {@link List} of {@link GFile} instances.
	 * @throws IOException if not a directory or error when accessing files.
	 */
	default public List<GFile> getListing() throws IOException {
		return getFilesystem().getListing(this);
	}

}
