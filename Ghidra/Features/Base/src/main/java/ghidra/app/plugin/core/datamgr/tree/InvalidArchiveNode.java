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

import java.util.List;

import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.InvalidFileArchive;
import ghidra.program.model.data.ArchiveType;
import ghidra.util.HTMLUtilities;

public class InvalidArchiveNode extends ArchiveNode {

	public InvalidArchiveNode(InvalidFileArchive archive) {
		super(archive, new ArrayPointerFilterState());
	}

	@Override
	public boolean isLeaf() {
		return true;
	}

	@Override
	public boolean isModifiable() {
		return false;
	}

	@Override
	public String getToolTip() {
		ArchiveType archiveType = ((InvalidFileArchive) archive).getArchiveType();
		String type = archiveType == ArchiveType.FILE ? "File" : "Project";
		return "<html>Unable to locate " + type + " data type archive: " +
			HTMLUtilities.escapeHTML(archive.getName());
	}

	@Override
	public String getName() {
		return archive.getName();
	}

	@Override
	public boolean canCut() {
		return false;
	}

	@Override
	public boolean canPaste(List<GTreeNode> pastedNodes) {
		return false;
	}

	@Override
	public ArchiveNode getArchiveNode() {
		return null;
	}

	@Override
	public boolean isCut() {
		return false;
	}

	@Override
	public boolean canDelete() {
		return false;
	}

	@Override
	public void setNodeCut(boolean isCut) {
	}

	@Override
	public Archive getArchive() {
		return archive;
	}

}
