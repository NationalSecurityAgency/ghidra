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

import ghidra.app.plugin.core.datamgr.archive.ProjectArchive;
import ghidra.framework.model.DomainFile;
import ghidra.util.HTMLUtilities;

public class ProjectArchiveNode extends DomainFileArchiveNode {

	public ProjectArchiveNode(ProjectArchive archive, ArrayPointerFilterState filterState) {
		super(archive, filterState);
	}

	@Override
	protected void dataTypeManagerChanged() {
		setChildren(null); // old children are no longer valid.
		installDataTypeManagerListener();
		nodeChanged();
	}

	@Override
	public String getToolTip() {
		DomainFile file = ((ProjectArchive) archive).getDomainFile();
		if (file != null) {
			return "<html>" + HTMLUtilities.escapeHTML(file.getPathname());
		}
		return "[Unsaved New Project Archive]";
	}

	public boolean hasWriteLock() {
		return false;
	}

	/**
	 * Overridden to avoid path conflicts that arise in CategoryNode.equals()
	 *
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (getClass() != o.getClass()) {
			return false;
		}

		if (super.equals(o)) {
			DomainFile myFile = ((ProjectArchive) archive).getDomainFile();
			DomainFile otherFile =
				((ProjectArchive) ((ProjectArchiveNode) o).archive).getDomainFile();
			return myFile.equals(otherFile);
		}
		return false;
	}

}
