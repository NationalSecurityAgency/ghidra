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
import java.util.Objects;

import javax.swing.Icon;

import generic.theme.GIcon;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.DataTypeArchive;

public class ProjectArchive implements DomainFileArchive {

	private static Icon CLOSED_ICON = new GIcon("icon.plugin.datatypes.archive.project.closed");
	private static Icon OPEN_ICON = new GIcon("icon.plugin.datatypes.archive.project.open");
	private DataTypeArchive dataTypeArchive;
	private DomainFile originalDomainFile;
	DataTypeManagerChangeListener categoryListener; // hold on to since it is stored in a weak set
	private DataTypeManagerHandler archiveManager;
	private DataTypeManager dataTypeManager;

	ProjectArchive(DataTypeManagerHandler archiveManager, DataTypeArchive dataTypeArchive,
			DomainFile originalDomainFile) {
		this.archiveManager = archiveManager;
		this.dataTypeArchive = dataTypeArchive;
		this.dataTypeManager = dataTypeArchive.getDataTypeManager();
		this.originalDomainFile = originalDomainFile;
		categoryListener = new ArchiveCategoryChangeListener();
		dataTypeManager.addDataTypeManagerListener(categoryListener);
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		return dataTypeManager;
	}

	@Override
	public String getName() {
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
	public int hashCode() {
		return originalDomainFile.getFileID().hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ProjectArchive other = (ProjectArchive) obj;
		return Objects.equals(originalDomainFile.getFileID(), other.originalDomainFile.getFileID());
	}

	public boolean hasExclusiveAccess() {
		return dataTypeArchive.hasExclusiveAccess();
	}

	@Override
	public boolean isModifiable() {
		DomainFile domainFile = getDomainObject().getDomainFile();
		return domainFile.canSave();
	}

	@Override
	public DomainFile getDomainFile() {
		return originalDomainFile;
	}

	@Override
	public DataTypeArchive getDomainObject() {
		return dataTypeArchive;
	}

	@Override
	public boolean isChanged() {
		DomainFile domainFile = dataTypeArchive.getDomainFile();
		long lastModifiedTime = domainFile.getLastModifiedTime();
		return (lastModifiedTime == 0) || dataTypeArchive.isChanged();
	}

	@Override
	public boolean isSavable() {
		return !dataTypeArchive.getDomainFile().isReadOnly() && dataTypeArchive.isChangeable();
	}

	@Override
	public void save() throws IOException {
		archiveManager.save(getDomainObject());
	}

	@Override
	public void close() {
		dataTypeManager.close();
		archiveManager.archiveClosed(this);
		dataTypeManager = null;
	}

	@Override
	public void saveAs(Component component) throws IOException {
		archiveManager.saveAs(dataTypeArchive);
		originalDomainFile = dataTypeArchive.getDomainFile();
		dataTypeArchive.updateID();
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
	}
}
