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
import java.io.IOException;

import javax.swing.Icon;

import generic.theme.GIcon;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.util.exception.ClosedException;

public class ProjectArchive implements DomainFileArchive {

	private static Icon CLOSED_ICON = new GIcon("icon.plugin.datatypes.archive.project.closed");
	private static Icon OPEN_ICON = new GIcon("icon.plugin.datatypes.archive.project.open");

	private DataTypeArchive dataTypeArchive;
	private DomainFile sourceDomainFile;
	private DataTypeManagerChangeListener categoryListener; // hold on to since it is stored in a weak set
	private DataTypeManagerHandler archiveManager;
	private StandAloneDataTypeManager dataTypeManager;

	ProjectArchive(DataTypeManagerHandler archiveManager, DataTypeArchive dataTypeArchive,
			DomainFile sourceDomainFile) {
		this.archiveManager = archiveManager;
		this.dataTypeArchive = dataTypeArchive;
		this.dataTypeManager = dataTypeArchive.getDataTypeManager();
		this.sourceDomainFile = sourceDomainFile;
		categoryListener = new ArchiveCategoryChangeListener();
		dataTypeManager.addDataTypeManagerListener(categoryListener);
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		return dataTypeManager;
	}

	@Override
	public String getName() {
		if (dataTypeManager == null) {
			return null;
		}
		return dataTypeManager.getName();
	}

	@Override
	public int compareTo(Archive archive) {
		if ((archive instanceof BuiltInArchive) || (archive instanceof ProgramArchive)) {
			return 1;
		}
		if (archive instanceof ProjectArchive) {
			return getName().compareToIgnoreCase(archive.getName());
		}
		return -1; // Project Archives appear between the ProgramArchive and FileArchives.
	}

	@Override
	public boolean hasExclusiveAccess() {
		return dataTypeArchive.hasExclusiveAccess();
	}

	@Override
	public boolean isModifiable() {
		if (dataTypeManager == null) {
			return false;
		}
		DomainFile df = getDomainObject().getDomainFile();
		return df.canSave();
	}

	@Override
	public DomainFile getDomainFile() {
		return sourceDomainFile;
	}

	@Override
	public DataTypeArchive getDomainObject() {
		return dataTypeArchive;
	}

	@Override
	public boolean isChanged() {
		if (dataTypeManager == null) {
			return false;
		}
		DomainFile df = dataTypeArchive.getDomainFile();
		long lastModifiedTime = df.getLastModifiedTime();
		return (lastModifiedTime == 0) || dataTypeArchive.isChanged();
	}

	@Override
	public boolean isSavable() {
		return dataTypeManager != null && !dataTypeArchive.getDomainFile().isReadOnly() &&
			dataTypeArchive.isChangeable();
	}

	@Override
	public void save() throws IOException {
		if (dataTypeManager == null) {
			throw new ClosedException();
		}
		archiveManager.save(getDomainObject());
	}

	@Override
	public void close() {
		if (dataTypeManager != null) {
			dataTypeManager.close();
			archiveManager.archiveClosed(this);
			dataTypeManager = null;
		}
	}

	@Override
	public void saveAs(Component component) throws IOException {
		if (dataTypeManager == null) {
			throw new ClosedException();
		}
		archiveManager.saveAs(dataTypeArchive);
		sourceDomainFile = dataTypeArchive.getDomainFile(); // update with new domain file
		dataTypeManager.updateID();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_ICON : CLOSED_ICON;
	}

	private void fireStateChanged() {
		archiveManager.fireArchiveStateChanged(this);
	}

	class ArchiveCategoryChangeListener implements DataTypeManagerChangeListener {
		@Override
		public void categoryAdded(DataTypeManager dtm, CategoryPath path) {
			fireStateChanged();
		}

		@Override
		public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
			fireStateChanged();
		}

		@Override
		public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
			fireStateChanged();
		}

		@Override
		public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath,
				CategoryPath newPath) {
			if (!oldPath.equals(newPath)) {
				fireStateChanged();
			}
		}

		@Override
		public void dataTypeAdded(DataTypeManager dtm, DataTypePath path) {
			fireStateChanged();
		}

		@Override
		public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
			fireStateChanged();
		}

		@Override
		public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
			fireStateChanged();
		}

		@Override
		public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {
			fireStateChanged();
		}

		@Override
		public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath) {
			fireStateChanged();
		}

		@Override
		public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath, DataType newDataType) {
			fireStateChanged();
		}

		@Override
		public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite) {
			// don't care
		}

		@Override
		public void sourceArchiveAdded(DataTypeManager dtm, SourceArchive dataTypeSource) {
			fireStateChanged();
		}

		@Override
		public void sourceArchiveChanged(DataTypeManager dtm, SourceArchive dataTypeSource) {
			fireStateChanged();
		}

		@Override
		public void programArchitectureChanged(DataTypeManager dtm) {
			fireStateChanged();
		}

		@Override
		public void restored(DataTypeManager dtm) {
			fireStateChanged();
		}
	}
}
