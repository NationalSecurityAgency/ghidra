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

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Interface that represents a filesystem that contains files.
 * <p>
 * Operations take a {@link TaskMonitor} if they need to be cancel-able.
 * <p>
 * Use {@link FileSystemService} to discover and open instances of filesystems in files or
 * to open a known {@link FSRL} path.
 * <p>
 * NOTE:<p>
 * ALL GFileSystem sub-CLASSES MUST END IN "FileSystem". If not, the ClassSearcher
 * will not find them.
 * <p>
 * Also note that this interface came after the original abstract class GFileSystem and its many
 * implementations, and usage is being migrated to this interface where possible and as
 * time permits.
 */
public interface GFileSystem extends Closeable, ExtensionPoint {
	/**
	 * File system volume name.
	 * <p>
	 * Typically the name of the container file, or a internally stored 'volume' name.
	 *
	 * @return string filesystem volume name.
	 */
	public String getName();

	/**
	 * Returns the type of this file system.
	 * <p>
	 * This default implementation returns the type value in {@link FileSystemInfo}
	 * annotation.
	 *
	 * @return type string
	 */
	default public String getType() {
		return FSUtilities.getFilesystemTypeFromClass(this.getClass());
	}

	/**
	 * Returns a description of this file system.
	 * <p>
	 * This default implementation returns the description value in {@link FileSystemInfo}
	 * annotation.
	 *
	 * @return description string
	 */
	default public String getDescription() {
		return FSUtilities.getFilesystemDescriptionFromClass(this.getClass());
	}

	/**
	 * File system's FSRL
	 *
	 * @return {@link FSRLRoot} of this filesystem.
	 */
	public FSRLRoot getFSRL();

	/**
	 * Returns true if the filesystem has been {@link #close() closed}
	 *
	 * @return boolean true if the filesystem has been closed.
	 */
	public boolean isClosed();

	/**
	 * Indicates if this filesystem is a static snapshot or changes.
	 *
	 * @return boolean true if the filesystem is static or false if dynamic content.
	 */
	default public boolean isStatic() {
		return true;
	}

	/**
	 * Returns the {@link FileSystemRefManager ref manager} that is responsible for
	 * creating and releasing {@link FileSystemRef refs} to this filesystem.
	 * <p>
	 * @return {@link FileSystemRefManager} that manages references to this filesystem.
	 */
	public FileSystemRefManager getRefManager();

	/**
	 * Returns the number of files in the filesystem, if known, otherwise -1 if not known.
	 *
	 * @return number of files in this filesystem, -1 if not known.
	 */
	default public int getFileCount() {
		return -1;
	}

	/**
	 * Retrieves a {@link GFile} from this filesystem based on its full path and filename.
	 * <p>
	 * @param path string path and filename of a file located in this filesystem.  Use 
	 * {@code null} or "/" to retrieve the root directory 
	 * @return {@link GFile} instance of requested file, null if not found.
	 * @throws IOException if IO error when looking up file.
	 */
	public GFile lookup(String path) throws IOException;

	/**
	 * Returns an {@link InputStream} that contains the contents of the specified {@link GFile}.
	 * <p>
	 * The caller is responsible for closing the stream.
	 * <p>
	 * @param file {@link GFile} to get an InputStream for
	 * @param monitor {@link TaskMonitor} to watch and update progress
	 * @return new {@link InputStream} contains the contents of the file or NULL if the
	 * file doesn't have data.
	 * @throws IOException if IO problem
	 * @throws CancelledException if user cancels.
	 */
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Returns a list of {@link GFile files} that reside in the specified directory on
	 * this filesystem.
	 * <p>
	 * @param directory NULL means root of filesystem.
	 * @return {@link List} of {@link GFile} instances of file in the requested directory.
	 * @throws IOException if IO problem.
	 */
	public List<GFile> getListing(GFile directory) throws IOException;

	/**
	 * Returns a multi-line string with information about the specified {@link GFile file}.
	 * <p>
	 * TODO:{@literal this method needs to be refactored to return a Map<String, String>; instead of}
	 * a pre-formatted multi-line string.
	 * <p>
	 * @param file {@link GFile} to get info message for.
	 * @param monitor {@link TaskMonitor} to watch and update progress.
	 * @return multi-line formatted string with info about the file, or null.
	 */
	default public String getInfo(GFile file, TaskMonitor monitor) {
		return null;
	}

}
