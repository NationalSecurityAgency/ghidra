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

import java.util.Collections;
import java.util.List;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.app.plugin.core.datamgr.archive.InvalidArchive;
import ghidra.util.HTMLUtilities;

/**
 * Archive node for an invalid file data type archive.
 */
public class InvalidArchiveNode extends DataTypeTreeNode {
	private static final Icon INVALID_ARCHIVE_ICON =
		new GIcon("icon.plugin.datatypes.archive.invalid");
	private InvalidArchive archive;

	public InvalidArchiveNode(InvalidArchive archive) {
		this.archive = archive;
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
		return "<html>Unable to locate file data type archive: " +
			HTMLUtilities.escapeHTML(archive.name());
	}

	@Override
	public String getName() {
		return archive.name();
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
	public FileArchiveNode getArchiveNode() {
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
		// do nothing
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return INVALID_ARCHIVE_ICON;
	}

	public InvalidArchive getInvalidArchive() {
		return archive;
	}

	@Override
	protected List<GTreeNode> generateChildren() {
		return Collections.emptyList();
	}
}
