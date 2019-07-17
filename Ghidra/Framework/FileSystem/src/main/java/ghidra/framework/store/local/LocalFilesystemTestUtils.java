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
package ghidra.framework.store.local;

import java.io.File;
import java.io.IOException;

public class LocalFilesystemTestUtils {

	private LocalFilesystemTestUtils() {
	}

	/**
	 * Create empty mangled filesystem
	 * @param rootPath path for root directory (must already exist).
	 * @param isVersioned if true item versioning will be enabled.
	 * @param readOnly if true modifications within this file-system will not be allowed
	 * and result in an ReadOnlyException
	 * @param enableAsyncronousDispatching if true a separate dispatch thread will be used
	 * to notify listeners.  If false, blocking notification will be performed.
	 * @throws IOException
	 */
	public static MangledLocalFileSystem createMangledFilesystem(String rootPath,
			boolean isVersioned, boolean readOnly, boolean enableAsyncronousDispatching)
			throws IOException {
		createRootDir(rootPath);
		return new MangledLocalFileSystem(rootPath, isVersioned, readOnly,
			enableAsyncronousDispatching);
	}

	/**
	 * Create empty original Indexed filesystem.  The original index file lacked any version indicator
	 * but will be treated as a version 0 index.
	 * @param rootPath path for root directory (must already exist).
	 * @param isVersioned if true item versioning will be enabled.
	 * @param readOnly if true modifications within this file-system will not be allowed
	 * and result in an ReadOnlyException
	 * @param enableAsyncronousDispatching if true a separate dispatch thread will be used
	 * to notify listeners.  If false, blocking notification will be performed.
	 * @throws IOException
	 */
	public static IndexedLocalFileSystem createOriginalIndexedFilesystem(String rootPath,
			boolean isVersioned, boolean readOnly, boolean enableAsyncronousDispatching)
			throws IOException {
		createRootDir(rootPath);

		return null;
	}

	/**
	 * Create empty V0 Indexed filesystem.  This is an original Indexed filesystem with the addition 
	 * of a version 0 indicator within the index file.
	 * @param rootPath path for root directory (must already exist).
	 * @param isVersioned if true item versioning will be enabled.
	 * @param readOnly if true modifications within this file-system will not be allowed
	 * and result in an ReadOnlyException
	 * @param enableAsyncronousDispatching if true a separate dispatch thread will be used
	 * to notify listeners.  If false, blocking notification will be performed.
	 * @throws IOException
	 */
	public static IndexedLocalFileSystem createIndexedV0Filesystem(String rootPath,
			boolean isVersioned, boolean readOnly, boolean enableAsyncronousDispatching)
			throws IOException {
		createRootDir(rootPath);
		return new IndexedLocalFileSystem(rootPath, isVersioned, readOnly,
			enableAsyncronousDispatching, true);
	}

	/**
	 * Create empty mangled filesystem
	 * @param rootPath path for root directory (must already exist).
	 * @param isVersioned if true item versioning will be enabled.
	 * @param readOnly if true modifications within this file-system will not be allowed
	 * and result in an ReadOnlyException
	 * @param enableAsyncronousDispatching if true a separate dispatch thread will be used
	 * to notify listeners.  If false, blocking notification will be performed.
	 * @throws IOException
	 */
	public static IndexedV1LocalFileSystem createIndexedV1Filesystem(String rootPath,
			boolean isVersioned, boolean readOnly, boolean enableAsyncronousDispatching)
			throws IOException {
		createRootDir(rootPath);
		return new IndexedV1LocalFileSystem(rootPath, isVersioned, readOnly,
			enableAsyncronousDispatching, true);
	}

	private static void createRootDir(String rootPath) throws IOException {
		File dir = new File(rootPath);
		if (!dir.isDirectory() && !dir.mkdirs()) {
			throw new IOException("Failed to create root directory: " + dir);
		}
	}

}
