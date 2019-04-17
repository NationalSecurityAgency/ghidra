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
package ghidra.framework.store.local;

import java.io.*;
import java.util.HashMap;

import ghidra.framework.store.FolderItem;
import ghidra.util.Msg;
import ghidra.util.PropertyFile;
import ghidra.util.exception.NotFoundException;

/**
 * <code>IndexedLocalFileSystem</code> implements a case-sensitive indexed filesystem
 * which uses a shallow storage hierarchy with no restriction on file name or path 
 * length.  This filesystem is identified by the existence of an index file (~index.dat) 
 * and recovery journal (~index.jrn).
 */
public class IndexedV1LocalFileSystem extends IndexedLocalFileSystem {

	public static final int INDEX_VERSION = IndexedLocalFileSystem.LATEST_INDEX_VERSION; // 1

	private HashMap<String, Item> fileIdMap;

	/**
	 * Constructor.
	 * @param file path path for root directory.
	 * @param isVersioned if true item versioning will be enabled.
	 * @param readOnly if true modifications within this file-system will not be allowed
	 * and result in an ReadOnlyException
	 * @param enableAsyncronousDispatching if true a separate dispatch thread will be used
	 * to notify listeners.  If false, blocking notification will be performed.
	 * @throws FileNotFoundException if specified rootPath does not exist
	 * @throws IOException if error occurs while reading/writing index files
	 */
	IndexedV1LocalFileSystem(String rootPath, boolean isVersioned, boolean readOnly,
			boolean enableAsyncronousDispatching, boolean create) throws IOException {
		super(rootPath, isVersioned, readOnly, enableAsyncronousDispatching, create);
	}

	/**
	 * Construct existing indexed filesystem with an empty index.
	 * This can be used to prepare for rebuilding the filesystem index.
	 * @param rootPath
	 * @throws IOException
	 */
	private IndexedV1LocalFileSystem(String rootPath) throws IOException {
		super(rootPath);
	}

	@Override
	public int getIndexImplementationVersion() {
		return INDEX_VERSION;
	}

	@Override
	String formatIndexItem(Item item) {
		String entry = item.getStorageName() + INDEX_ITEM_SEPARATOR + item.getName();
		String fileId = item.getFileID();
		if (fileId != null) {
			entry += INDEX_ITEM_SEPARATOR + fileId;
		}
		return entry;
	}

	@Override
	Item parseIndexItem(Folder parent, String entry) {
		int index = entry.indexOf(INDEX_ITEM_SEPARATOR);
		if (index < 0) {
			return null;
		}
		String storageName = entry.substring(0, index);
		String name = entry.substring(index + 1);
		String fileId = null;
		index = name.indexOf(INDEX_ITEM_SEPARATOR);
		if (index > 0) {
			fileId = name.substring(index + 1);
			name = name.substring(0, index);
		}
		return new Item(parent, name, fileId, storageName);
	}

	@Override
	protected synchronized void fileIdChanged(PropertyFile pfile, String oldFileId)
			throws IOException {
		indexJournal.open();
		try {
			Folder folder = getFolder(pfile.getParentPath(), GetFolderOption.READ_ONLY);
			Item item = folder.items.get(pfile.getName());
			if (item == null) {
				throw new NotFoundException(pfile.getPath());
			}
			item.setFileID(pfile.getFileID());

			indexJournal.fileIdSet(pfile.getPath(), pfile.getFileID());
		}
		catch (NotFoundException e) {
			throw new FileNotFoundException(e.getMessage());
		}
		finally {
			indexJournal.close();
		}
	}

	private HashMap<String, Item> getFileIdMap() {
		if (fileIdMap == null) {
			fileIdMap = new HashMap<>();
		}
		return fileIdMap;
	}

	@Override
	void mapFileID(String fileId, Item item) {
		getFileIdMap().put(fileId, item);
	}

	@Override
	void unmapFileID(String fileId) {
		getFileIdMap().remove(fileId);
	}

	@Override
	public FolderItem getItem(String fileID) throws IOException, UnsupportedOperationException {
		if (fileIdMap == null) {
			return null;
		}
		Item item = fileIdMap.get(fileID);
		if (item == null) {
			return null;
		}
		try {
			PropertyFile propertyFile = item.itemStorage.getPropertyFile();
			if (propertyFile.exists()) {
				return LocalFolderItem.getFolderItem(this, propertyFile);
			}
		}
		catch (FileNotFoundException e) {
			// ignore
		}
		return null;
	}

	/**
	 * Get the V0 indexed-file-system instance.  File system storage should first be 
	 * pre-qualified as an having indexed storage using the {@link #isIndexed(String)} method
	 * and have the correct version.
	 * @param rootPath
	 * @param isVersioned
	 * @param readOnly
	 * @param enableAsyncronousDispatching
	 * @return file-system instance
	 * @throws IOException
	 */
	static IndexedV1LocalFileSystem getFileSystem(String rootPath, boolean isVersioned,
			boolean readOnly, boolean enableAsyncronousDispatching) throws IOException {
		try {
			return new IndexedV1LocalFileSystem(rootPath, isVersioned, readOnly,
				enableAsyncronousDispatching, false);
		}
		catch (IndexReadException e) {
			if (readOnly) {
				throw e; // don't attempt repair if read-only
			}

			Msg.error(LocalFileSystem.class, "Indexed filesystem error: " + e.getMessage());

			Msg.info(LocalFileSystem.class, "Attempting index rebuild: " + rootPath);
			if (!IndexedV1LocalFileSystem.rebuild(new File(rootPath))) {
				throw e;
			}

			// retry after index rebuild
			return new IndexedV1LocalFileSystem(rootPath, isVersioned, readOnly,
				enableAsyncronousDispatching, false);
		}
	}

	/**
	 * Completely rebuild filesystem index using item information contained
	 * within indexed property files.  Empty folders will be lost.
	 * @param rootDir
	 * @throws IOException
	 */
	public static boolean rebuild(File rootDir) throws IOException {

		verifyIndexedFileStructure(rootDir);

		IndexedV1LocalFileSystem fs = new IndexedV1LocalFileSystem(rootDir.getAbsolutePath());
		fs.rebuildIndex();
		fs.cleanupAfterConstruction();
		fs.dispose();

		File errorFile = new File(rootDir, REBUILD_ERROR_FILE);
		if (errorFile.exists()) {
			Msg.error(LocalFileSystem.class,
				"Indexed filesystem rebuild failed, see log for details: " + errorFile);
			return false;
		}
		Msg.info(LocalFileSystem.class, "Index rebuild completed: " + rootDir);
		return true;
	}

}
