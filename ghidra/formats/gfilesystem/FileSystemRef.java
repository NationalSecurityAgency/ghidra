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

import ghidra.util.Msg;

import java.io.Closeable;

/**
 * A handle to a {@link GFileSystem} which allows tracking the current users of the filesystem.
 * <p>
 * Instances must be {@link #close() closed} when not needed anymore, and should not be
 * shared across threads.
 */
public class FileSystemRef implements Closeable {
	private final GFileSystem fs;
	private boolean refClosed = false;

	/**
	 * Protected constructor, instances are created by {@link FileSystemRefManager}.
	 *
	 * @param fs {@link GFileSystem} this ref points to.
	 */
	FileSystemRef(GFileSystem fs) {
		this.fs = fs;
	}

	/**
	 * Creates a duplicate ref.
	 *
	 * @return a new duplicate {@link FileSystemRef}
	 */
	public FileSystemRef dup() {
		return fs.getRefManager().create();
	}

	/**
	 * {@link GFileSystem} this ref points to.
	 *
	 * @return {@link GFileSystem} this ref points to.
	 */
	public GFileSystem getFilesystem() {
		return fs;
	}

	/**
	 * Closes this reference, releasing it from the {@link FileSystemRefManager}.
	 */
	@Override
	public void close() {
		fs.getRefManager().release(this);
		refClosed = true;
	}

	/**
	 * Returns true if this ref was {@link #close() closed}.
	 * <p>
	 * @return boolean true if this ref was closed.
	 */
	public boolean isClosed() {
		return refClosed;
	}

	@Override
	public void finalize() {
		if (!refClosed) {
			Msg.warn(this, "Unclosed FilesytemRef: " + fs.toString());
		}
	}
}
