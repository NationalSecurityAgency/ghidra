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

import javax.swing.ImageIcon;

import ghidra.program.model.data.*;
import ghidra.util.UniversalID;
import ghidra.util.exception.DuplicateFileException;
import resources.ResourceManager;

public class InvalidFileArchive implements Archive {

	private static final ImageIcon INVALID_ARCHIVE_ICON =
		ResourceManager.loadImage("images/closedFolderInvalid.png");
	private DataTypeManagerHandler archiveManager;
	private UniversalID universalID;
	private ArchiveType archiveType;
	private String name;
	private String domainFileID;

	InvalidFileArchive(DataTypeManagerHandler archiveManager, SourceArchive sourceArchive) {
		this.archiveManager = archiveManager;
		this.universalID = sourceArchive.getSourceArchiveID();
		this.archiveType = sourceArchive.getArchiveType();
		this.name = sourceArchive.getName();
		this.domainFileID = sourceArchive.getDomainFileID();
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		return null;
	}

	@Override
	public boolean isModifiable() {
		return false;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int compareTo(Archive archive) {
		if (archive instanceof InvalidFileArchive) {
			return getName().compareToIgnoreCase(archive.getName());
		}
		return 1;
	}

	public ArchiveType getArchiveType() {
		return archiveType;
	}

	public String getDomainFileID() {
		return domainFileID;
	}

	@Override
	public void close() {
		archiveManager.archiveClosed(this);
	}

	@Override
	public boolean isChanged() {
		return false;
	}

	@Override
	public boolean isSavable() {
		return false;
	}

	@Override
	public void save() throws DuplicateFileException, IOException {
		// Can't "Save" so do nothing.
	}

	@Override
	public void saveAs(Component component) throws IOException {
		// Can't "Save As" so do nothing.
	}

	public UniversalID getUniversalID() {
		return universalID;
	}

	@Override
	public ImageIcon getIcon(boolean expanded) {
		return INVALID_ARCHIVE_ICON;
	}
}
