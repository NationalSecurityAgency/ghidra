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
package ghidra.app.plugin.core.datamgr.tree;

import javax.swing.Icon;

import generic.theme.GIcon;
import ghidra.framework.data.DomainFileProxy;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.dtarchive.ProjectDataTypeArchive;
import ghidra.util.HTMLUtilities;

/**
 * Tree node for representing open project datatype archives.
 */
public class ProjectArchiveNode extends ArchiveNode implements VersionedNode {
	private static Icon CLOSED_ICON = new GIcon("icon.plugin.datatypes.archive.project.closed");
	private static Icon OPEN_ICON = new GIcon("icon.plugin.datatypes.archive.project.open");
	private VersionState versionState;

	public ProjectArchiveNode(ProjectDataTypeArchive archive, DtFilterState filterState) {
		super(archive, filterState);
		versionState = new VersionState(archive);
	}

	@Override
	public String getToolTip() {
		DomainFile file = getDomainObject().getDomainFile();
		DomainFile originalFile = file;
		if (file instanceof DomainFileProxy proxy) {
			originalFile = proxy.getOriginalDomainFile();
		}
		StringBuilder buf = new StringBuilder(HTMLUtilities.HTML);
		if (originalFile != null) {
			buf.append(HTMLUtilities.escapeHTML(originalFile.toString()));
		}
		else {
			buf.append("[Unsaved Project Archive]");
		}
		buf.append(HTMLUtilities.BR);
		buf.append(getArchitectureDetails());
		buf.append(HTMLUtilities.HTML_CLOSE);
		return buf.toString();
	}

	public boolean hasWriteLock() {
		return false;
	}

	@Override
	public void nodeChanged() {
		super.nodeChanged();
		versionState.updateDomainFileInfo();
	}

	@Override
	public DomainObject getDomainObject() {
		return getArchive();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		Icon baseIcon = expanded ? OPEN_ICON : CLOSED_ICON;
		return versionState.getIcon(baseIcon);
	}

	@Override
	public ProjectDataTypeArchive getArchive() {
		return (ProjectDataTypeArchive) super.getArchive();
	}

	@Override
	public String getDomainObjectInfo() {
		return versionState.getDomainObjectInfo();
	}

	@Override
	public DomainFile getOriginalDomainFile() {
		return versionState.getOriginalDomainFile();
	}

	@Override
	public DomainFile getDomainFile() {
		return archive.getDomainFile();
	}
}
