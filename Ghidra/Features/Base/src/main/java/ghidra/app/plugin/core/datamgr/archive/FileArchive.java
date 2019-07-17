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
package ghidra.app.plugin.core.datamgr.archive;

import java.awt.Component;
import java.io.File;
import java.io.IOException;

import javax.swing.ImageIcon;

import generic.jar.ResourceFile;
import ghidra.framework.store.LockException;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateFileException;
import resources.ResourceManager;

/**
 * Manages a DataTypeFileManager and relative state.  For example, whether the manager is writable
 * or whether changes have been made.
 */
public class FileArchive implements Archive {

	private static ImageIcon CLOSED_ICON = ResourceManager.loadImage("images/closedBookGreen.png");
	private static ImageIcon OPEN_ICON = ResourceManager.loadImage("images/openBookGreen.png");
	private ResourceFile archiveFile;
	private boolean hasWriteLock;
	private boolean changed;
	private DataTypeManagerHandler archiveManager;
	private FileDataTypeManager fileDataTypeManager;
	DataTypeManagerChangeListener categoryListener; // hold on to since it is stored in a weak set
	private String name;

	FileArchive(DataTypeManagerHandler archiveManager, File file) throws IOException {
		this(archiveManager, FileDataTypeManager.createFileArchive(file));
		archiveFile = new ResourceFile(file.getCanonicalFile());
		hasWriteLock = true;
	}

	FileArchive(DataTypeManagerHandler archiveManager, ResourceFile file, boolean acquireWriteLock)
			throws IOException {
		this(archiveManager, FileDataTypeManager.openFileArchive(file, acquireWriteLock));
		this.archiveFile = file.getCanonicalFile();
		this.hasWriteLock = acquireWriteLock;
	}

	private FileArchive(DataTypeManagerHandler archiveManager, FileDataTypeManager manager) {
		this.archiveManager = archiveManager;
		this.fileDataTypeManager = manager;
		categoryListener = new ArchiveCategoryChangeListener();
		manager.addDataTypeManagerListener(categoryListener);
		name = fileDataTypeManager.getName();
		changed = fileDataTypeManager.isChanged(); // may have immediately changed due to upgrade
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int compareTo(Archive archive) {
		if ((archive instanceof BuiltInArchive) || (archive instanceof ProgramArchive) ||
			(archive instanceof ProjectArchive)) {
			return 1;
		}
		if (archive instanceof FileArchive) {
			return getName().compareToIgnoreCase(archive.getName());
		}
		return -1; // File Archives appear between ProjectArchives and InvalidFileArchives.
	}

	@Override
	public void close() {
		fileDataTypeManager.removeDataTypeManagerListener(categoryListener);
		fileDataTypeManager.close();
		archiveManager.archiveClosed(this);
		fileDataTypeManager = null;
	}

	public void delete() throws IOException {
		fileDataTypeManager.removeDataTypeManagerListener(categoryListener);
		fileDataTypeManager.delete();
		archiveManager.archiveClosed(this);
		fileDataTypeManager = null;
	}

	public void acquireWriteLock() throws LockException, IOException {
		refreshArchive(true);
		hasWriteLock = true;
		fireStateChanged();
	}

	public void releaseWriteLock() throws IOException {
		try {
			refreshArchive(false);
		}
		catch (LockException e) {
			// we know this can't happen, since we are already have the write lock
		}
		hasWriteLock = false;
		setChanged(false);
	}

	public void saveAs(File file) throws DuplicateFileException, IOException {
		File newFile = FileDataTypeManager.convertFilename(file);
		fileDataTypeManager.saveAs(newFile);
		archiveFile = new ResourceFile(newFile);
		hasWriteLock = true;
		setChanged(false);
	}

	@Override
	public void save() throws IOException {
		fileDataTypeManager.save();
		setChanged(false);
	}

	public ResourceFile getFile() {
		return archiveFile;
	}

	public boolean hasWriteLock() {
		return hasWriteLock;
	}

	@Override
	public boolean isChanged() {
		if (isClosed()) {
			return false;
		}
		return changed || fileDataTypeManager.isChanged();
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		return fileDataTypeManager;
	}

	boolean isClosed() {
		return fileDataTypeManager == null;
	}

	@Override
	public boolean isSavable() {
		return (archiveFile != null);
	}

	@Override
	public boolean isModifiable() {
		return hasWriteLock();
	}

	public DataTypeManagerHandler getArchiveManager() {
		return archiveManager;
	}

	private void fireStateChanged() {
		archiveManager.fireArchiveStateChanged(this);
	}

	/**
	 * Re-read the archive file.
	 * @param forUpdate true indicates to open the database for update, false for read-only.
	 * @throws LockException if the open if for update and a lock could not
	 * be obtained
	 * @throws IOException if the archive file can't be opened
	 */
	private void refreshArchive(boolean forUpdate) throws LockException, IOException {

		// re-read archive file if it isn't null
		if (archiveFile != null) {
			FileDataTypeManager newManager =
				FileDataTypeManager.openFileArchive(archiveFile, forUpdate);

			FileDataTypeManager oldManager = fileDataTypeManager;
			oldManager.removeDataTypeManagerListener(categoryListener);
			oldManager.close();

			fileDataTypeManager = newManager;
			fileDataTypeManager.addDataTypeManagerListener(categoryListener);

			archiveManager.dataTypeManagerChanged(this, oldManager, newManager);
		}
	}

	private void setChanged(boolean change) {
		if (changed == change) {
			return;
		}
		changed = change;
		fireStateChanged();
	}

	class ArchiveCategoryChangeListener implements DataTypeManagerChangeListener {
		@Override
		public void categoryAdded(DataTypeManager dtm, CategoryPath path) {
			setChanged(true);
		}

		@Override
		public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
			setChanged(true);
		}

		@Override
		public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
			setChanged(true);
		}

		@Override
		public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath,
				CategoryPath newPath) {
			if (!oldPath.equals(newPath)) {
				setChanged(true);
			}
		}

		@Override
		public void dataTypeAdded(DataTypeManager dtm, DataTypePath path) {
			setChanged(true);
		}

		@Override
		public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
			setChanged(true);
		}

		@Override
		public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
			setChanged(true);
		}

		@Override
		public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {
			setChanged(true);
		}

		@Override
		public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath) {
			setChanged(true);
		}

		@Override
		public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath, DataType newDataType) {
			setChanged(true);
		}

		@Override
		public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite) {
			// don't care
		}

		@Override
		public void sourceArchiveAdded(DataTypeManager dtm, SourceArchive dataTypeSource) {
			setChanged(true);
		}

		@Override
		public void sourceArchiveChanged(DataTypeManager dtm, SourceArchive dataTypeSource) {
			setChanged(true);
		}
	}

	@Override
	public void saveAs(Component component) throws IOException {
		File saveAsFile = ArchiveUtils.getFile(component, this);
		if (saveAsFile == null) {
			return;
		}

		if (saveAsFile.equals(getFile())) {
			save();
		}
		else {
			saveAs(saveAsFile);
		}
	}

	@Override
	public ImageIcon getIcon(boolean expanded) {
		return expanded ? OPEN_ICON : CLOSED_ICON;
	}
}
