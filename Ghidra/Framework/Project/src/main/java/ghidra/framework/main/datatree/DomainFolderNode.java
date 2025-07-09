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
package ghidra.framework.main.datatree;

import java.io.IOException;
import java.util.List;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import ghidra.framework.model.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * Class to represent a node in the Data tree.
 */
public class DomainFolderNode extends DataTreeNode {

	private static final Icon ENABLED_OPEN_FOLDER = DomainFolder.OPEN_FOLDER_ICON;
	private static final Icon ENABLED_CLOSED_FOLDER = DomainFolder.CLOSED_FOLDER_ICON;

	private static final Icon DISABLED_OPEN_FOLDER =
		ResourceManager.getDisabledIcon(ENABLED_OPEN_FOLDER);
	private static final Icon DISABLED_CLOSED_FOLDER =
		ResourceManager.getDisabledIcon(ENABLED_CLOSED_FOLDER);

	private DomainFolder domainFolder;
	private DomainFileFilter filter;

	// variables that are accessed in with a lock on the filesystem in the underlying folder
	private String toolTipText;
	private boolean isEditable;

	DomainFolderNode(DomainFolder domainFolder, DomainFileFilter filter) {
		this.domainFolder = domainFolder;
		this.filter = filter;

		// TODO: how can the folder be null?...doesn't really make sense...I don't think it ever is
		if (domainFolder != null) {
			setToolTipText();
			isEditable = domainFolder.isInWritableProject();
		}
	}

	@Override
	public boolean isAutoExpandPermitted() {
		// Prevent auto-expansion through linked-folders
		return !domainFolder.isLinked();
	}

	/**
	 * Get the domain folder; returns null if this node represents a domain file.
	 *
	 * @return DomainFolder
	 */
	public DomainFolder getDomainFolder() {
		return domainFolder;
	}

	/**
	 * Returns true if this node has no children.
	 */
	@Override
	public boolean isLeaf() {
		return false;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (isCut()) {
			return expanded ? DISABLED_OPEN_FOLDER : DISABLED_CLOSED_FOLDER;
		}
		return expanded ? ENABLED_OPEN_FOLDER : ENABLED_CLOSED_FOLDER;
	}

	@Override
	public String getName() {
		return domainFolder.getName();
	}

	@Override
	public String toString() {
		return getName();
	}

	@Override
	public String getToolTip() {
		return toolTipText;
	}

	private void setToolTipText() {
		String newToolTipText;
		if (domainFolder instanceof LinkedDomainFolder) {
			newToolTipText = domainFolder.toString();
		}
		else {
			newToolTipText = domainFolder.getPathname();
		}
		toolTipText = HTMLUtilities.toLiteralHTML(newToolTipText, 0);
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		return generateChildren(domainFolder, filter, monitor);
	}

	@Override
	public boolean isEditable() {
		return isEditable;
	}

	@Override
	public boolean equals(Object obj) {

		if (obj == null) {
			return false;
		}
		if (this == obj) {
			return true;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		DomainFolderNode node = (DomainFolderNode) obj;
		if (domainFolder.equals(node.domainFolder)) {
			return true;
		}
		return false;
	}

	@Override
	public int hashCode() {
		return domainFolder.hashCode();
	}

	public DomainFileFilter getDomainFileFilter() {
		return filter;
	}

	@Override
	public int compareTo(GTreeNode node) {
		return DATA_NODE_SORT_COMPARATOR.compare(this, node);
	}

	@Override
	public void valueChanged(Object newValue) {
		if (newValue.equals(getName())) {
			return;
		}

		if (newValue instanceof String) {
			try {
				domainFolder.setName((String) newValue);
			}
			catch (InvalidNameException e) {
				Msg.showError(this, getTree(), "Rename Failed", "Invalid name: " + newValue);
			}
			catch (IOException e) {
				Msg.showError(this, getTree(), "Rename Failed", e.getMessage());
			}
		}
	}

	@Override
	public GTreeNode getChild(String name, NodeType type) {
		return getChild(children(), name, type);
	}

	@Override
	public ProjectData getProjectData() {
		return domainFolder.getProjectData();
	}
}
