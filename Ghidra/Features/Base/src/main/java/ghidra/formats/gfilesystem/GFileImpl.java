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

import java.util.Objects;

/**
 * Base implementation of file in a {@link GFileSystem filesystem}.
 * <p>
 * Only valid while the owning filesystem object is still open and not
 * {@link GFileSystem#close() closed}.
 * <p>
 * See {@link GFile}.
 */
public class GFileImpl implements GFile {

	/**
	 * Creates a GFile for a filesystem using a string
	 * path (ie. "dir/subdir/filename"), with the path starting at the root of the
	 * filesystem.
	 * <p>
	 * The parents of this GFile are created fresh from any directory names
	 * in the path string.  It is better to use the
	 * {@link #fromFilename(GFileSystem, GFile, String, boolean, long, FSRL)} method
	 * to create GFile instances if you can supply the parent value as that will
	 * allow reuse of the parent objects instead of duplicates of them being created
	 * for each file with the same parent path.
	 *
	 * @param fileSystem the {@link GFileSystem} that owns this file
	 * @param path forward slash '/' separated path and filename string.
	 * @param fsrl {@link FSRL} to assign to the file, NULL if an auto-created FSRL is ok.
	 * @param isDirectory boolean flag to indicate that this is a directory
	 * @param length length of the file (use -1 if not know or specified).
	 * @return a new {@link GFileImpl}
	 */
	public static GFileImpl fromPathString(GFileSystem fileSystem, String path, FSRL fsrl,
			boolean isDirectory, long length) {
		return fromPathString(fileSystem, null, path, fsrl, isDirectory, length);
	}

	/**
	 * Creates a GFile for a specific owning filesystem using a string
	 * path (ie. "dir/subdir/filename"), with the path starting at the supplied
	 * {@code parent} directory.
	 * <p>
	 * The parents of this GFile are created fresh from any directory names
	 * in the path string.  It is better to use the
	 * {@link #fromFilename(GFileSystem, GFile, String, boolean, long, FSRL)} method
	 * to create GFile instances if you can supply the parent value as that will
	 * allow reuse of the parent objects instead of duplicates of them being created
	 * for each file with the same parent path.
	 *
	 * @param fileSystem the {@link GFileSystem} that owns this file
	 * @param parent the parent of the new GFile or null if child-of-root.
	 * @param path forward slash '/' separated path and filename string.
	 * @param fsrl {@link FSRL} to assign to the file, NULL if an auto-created FSRL is ok.
	 * @param isDirectory boolean flag to indicate that this is a directory
	 * @param length length of the file (use -1 if not know or specified).
	 * @return a new {@link GFileImpl}
	 */
	public static GFileImpl fromPathString(GFileSystem fileSystem, GFile parent, String path,
			FSRL fsrl, boolean isDirectory, long length) {
		String[] split = path.split(FSUtilities.SEPARATOR);
		if (split.length >= 3 && split[0].isEmpty() && split[1].isEmpty() && !split[2].isEmpty()) {
			// The path was in UNC format, either //unc or \\unc.
			// Put a unc prefix "//" back into the element that has the unc name.  The leading empty
			// elements will be skipped when building the parentage.
			split[2] = "//" + split[2];
		}
		for (int i = 0; i < split.length - 1; ++i) {
			if (split[i].length() == 0) {
				continue;
			}
			parent = fromFilename(fileSystem, parent, split[i], true, -1, null);
		}
		if (fsrl == null) {
			String filename = split.length > 0 ? split[split.length - 1] : "/";
			fsrl = getFSRLFromParent(fileSystem, parent, filename);
		}
		return new GFileImpl(fileSystem, parent, isDirectory, length, fsrl);
	}

	/**
	 * Creates a FSRL for a file based on the either the filesystem's FSRLRoot or parent
	 * directory's FSRL, preferring a parent directory over the filesystem's FSRL.
	 *
	 * @param fs {@link GFileSystem}
	 * @param parent {@link GFile} parent directory, null ok
	 * @param path string path to assign to the FSRL
	 * @return new {@link FSRL}
	 */
	private static FSRL getFSRLFromParent(GFileSystem fs, GFile parent, String path) {
		FSRL parentFSRL = (parent != null) ? parent.getFSRL() : fs.getFSRL();
		return parentFSRL.appendPath(path);
	}

	/**
	 * Creates a GFile for a filesystem using a simple name (not a path)
	 * and as a child of the specified parent.
	 * <p>
	 * The filename is accepted without checking or validation.
	 * 
	 * @param fileSystem the {@link GFileSystem} that owns this file
	 * @param parent the parent of the new GFile or null if child-of-root.
	 * @param filename the file's name, not used if FSRL param specified.
	 * @param isDirectory boolean flag to indicate that this is a directory
	 * @param length length of the file (use -1 if not know or specified).
	 * @param fsrl {@link FSRL} to assign to the file, NULL if an auto-created FSRL is ok.
	 * @return a new {@link GFileImpl}
	 */
	public static GFileImpl fromFilename(GFileSystem fileSystem, GFile parent, String filename,
			boolean isDirectory, long length, FSRL fsrl) {
		if (fsrl == null) {
			fsrl = getFSRLFromParent(fileSystem, parent, filename);
		}
		return new GFileImpl(fileSystem, parent, isDirectory, length, fsrl);
	}

	/**
	 * Creates a GFile for a filesystem using the information in a FSRL as the file's name
	 * and as a child of the specified parent.
	 * 
	 * @param fileSystem the {@link GFileSystem} that owns this file
	 * @param parent the parent of the new GFile or null if child-of-root.
	 * @param fsrl {@link FSRL} to assign to the file.
	 * @param isDirectory boolean flag to indicate that this is a directory
	 * @param length length of the file (use -1 if not know or specified).
	 * @return a new {@link GFileImpl}
	 */
	public static GFileImpl fromFSRL(GFileSystem fileSystem, GFile parent, FSRL fsrl,
			boolean isDirectory, long length) {
		return new GFileImpl(fileSystem, parent, isDirectory, length, fsrl);
	}

	private final GFileSystem fileSystem;
	private final GFile parentFile;
	private final boolean isDirectory;
	private long length;
	private final FSRL fsrl;

	/**
	 * Protected constructor, use static helper methods to create new instances.
	 * <p>
	 * Creates a new GFile instance without any name parsing.
	 *
	 * @param fileSystem the {@link GFileSystem} that owns this file
	 * @param parentFile the parent of the new GFile or null if child-of-root.
	 * @param isDirectory boolean flag to indicate that this is a directory
	 * @param length length of the file (use -1 if not know or specified).
	 * @param fsrl {@link FSRL} to assign to the file.
	 */
	protected GFileImpl(GFileSystem fileSystem, GFile parentFile, boolean isDirectory, long length,
			FSRL fsrl) {
		this.fileSystem = fileSystem;
		this.fsrl = fsrl;
		this.parentFile = parentFile;
		this.isDirectory = isDirectory;
		this.length = length;
	}

	@Override
	public GFile getParentFile() {
		return parentFile;
	}

	@Override
	public String getName() {
		return fsrl.getName();
	}

	@Override
	public boolean isDirectory() {
		return isDirectory;
	}

	@Override
	public long getLength() {
		return length;
	}

	@Override
	public GFileSystem getFilesystem() {
		return fileSystem;
	}

	@Override
	public String toString() {
		return getPath();
	}

	@Override
	public String getPath() {
		return fsrl.getPath();
	}

	public void setLength(long length) {
		this.length = length;
	}

	@Override
	public FSRL getFSRL() {
		return fsrl;
	}

	@Override
	public int hashCode() {
		return Objects.hash(fileSystem, fsrl.getPath(), isDirectory);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof GFile)) {
			return false;
		}
		GFile other = (GFile) obj;
		return Objects.equals(fileSystem, other.getFilesystem()) &&
			Objects.equals(fsrl.getPath(), other.getFSRL().getPath()) &&
			isDirectory == other.isDirectory();
	}
}
