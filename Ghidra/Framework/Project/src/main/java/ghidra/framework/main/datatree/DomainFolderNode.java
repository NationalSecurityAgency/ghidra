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
import java.util.*;

import javax.swing.Icon;

import docking.widgets.tree.GTreeLazyNode;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.model.*;
import ghidra.util.*;
import resources.ResourceManager;

/**
 * Class to represent a node in the Data tree.
 */
public class DomainFolderNode extends GTreeLazyNode implements Cuttable {

	private static final Icon ENABLED_OPEN_FOLDER = DomainFolder.OPEN_FOLDER_ICON;
	private static final Icon ENABLED_CLOSED_FOLDER = DomainFolder.CLOSED_FOLDER_ICON;

	private static final Icon DISABLED_OPEN_FOLDER =
		ResourceManager.getDisabledIcon(ENABLED_OPEN_FOLDER);
	private static final Icon DISABLED_CLOSED_FOLDER =
		ResourceManager.getDisabledIcon(ENABLED_CLOSED_FOLDER);

	private DomainFolder domainFolder;
	private boolean isCut;
	private DomainFileFilter filter;

	// variables that are accessed in with a lock on the filesystem in the underlying folder
	private String toolTipText;
	private boolean isEditable;

	DomainFolderNode(DomainFolder domainFolder, DomainFileFilter filter) {
		this.domainFolder = domainFolder;
		this.filter = filter;

		// TODO: how can the folder be null?...doesn't really make sense...I don't think it ever is
		if (domainFolder != null) {
			toolTipText = StringUtilities.trimMiddle(domainFolder.getPathname(), 120);
			toolTipText = HTMLUtilities.toLiteralHTML(toolTipText, 0);
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

	/**
	 * Set this node to be deleted so that it can be rendered as such.
	 */
	@Override
	public void setIsCut(boolean isCut) {
		this.isCut = isCut;
		fireNodeChanged();
	}

	/**
	 * Returns whether this node is marked as deleted.
	 */
	@Override
	public boolean isCut() {
		return isCut;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (domainFolder instanceof LinkedDomainFolder) {
			// NOTE: cut operation not supported
			return ((LinkedDomainFolder) domainFolder).getIcon(expanded);
		}
		if (expanded) {
			return isCut ? DISABLED_OPEN_FOLDER : ENABLED_OPEN_FOLDER;
		}
		return isCut ? DISABLED_CLOSED_FOLDER : ENABLED_CLOSED_FOLDER;
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

	@Override
	protected List<GTreeNode> generateChildren() {

		List<GTreeNode> children = new ArrayList<>();
		if (domainFolder != null && !domainFolder.isEmpty()) {

			// NOTE: isEmpty() is used to avoid multiple failed connection attempts on this folder

			DomainFolder[] folders = domainFolder.getFolders();
			for (DomainFolder folder : folders) {
				children.add(new DomainFolderNode(folder, filter));
			}

			DomainFile[] files = domainFolder.getFiles();
			for (DomainFile domainFile : files) {
				if (domainFile.isLinkFile() && filter != null && filter.followLinkedFolders()) {
					DomainFolder folder = domainFile.followLink();
					if (folder != null) {
						children.add(new DomainFolderNode(folder, filter));
						continue;
					}
				}
				if (filter == null || filter.accept(domainFile)) {
					children.add(new DomainFileNode(domainFile));
				}
			}
		}
		Collections.sort(children);
		return children;
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
		return System.identityHashCode(domainFolder);
	}

	public DomainFileFilter getDomainFileFilter() {
		return filter;
	}

	@Override
	public int compareTo(GTreeNode node) {
		if (node instanceof DomainFileNode) {
			// defer to DomainFileNode for comparison
			return -((DomainFileNode) node).compareTo(this);
		}
		return super.compareTo(node);
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
}
