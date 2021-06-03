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
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.swing.Icon;
import javax.swing.SwingWorker;

import docking.widgets.tree.GTreeNode;
import ghidra.framework.model.DomainFile;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.util.*;
import ghidra.util.exception.DuplicateFileException;
import resources.ResourceManager;

/**
 * Class to represent a node in the Data tree.
 */
public class DomainFileNode extends GTreeNode implements Cuttable {

	private static final Icon UNKNOWN_FILE_ICON =
		ResourceManager.loadImage("images/unknownFile.gif");

	private final DomainFile domainFile;

	private volatile String displayName; // name displayed in the tree
	private volatile Icon icon = UNKNOWN_FILE_ICON;
	private volatile Icon disabledIcon;
	protected volatile String toolTipText;

	private volatile boolean isCut; // true if this node is marked as cut

	private final SimpleDateFormat formatter = new SimpleDateFormat("yyyy MMM dd hh:mm aaa");

	/**
	 * Construct a node for a domain file.
	 */
	DomainFileNode(DomainFile domainFile) {
		this.domainFile = domainFile;
		displayName = domainFile.getName();
		refresh();
	}

	/**
	 * Get the domain file if this node represents a file object versus
	 * a folder; interface method for DomainDataTransfer.
	 * @return null if this node represents a domain folder
	 */
	public DomainFile getDomainFile() {
		return domainFile;
	}

	/**
	 * Returns true if this node has no children.
	 */
	@Override
	public boolean isLeaf() {
		return true;
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
		DomainFileNode node = (DomainFileNode) obj;
		if (domainFile == node.domainFile) {
			return true;
		}
		return false;
	}

	@Override
	public int hashCode() {
		return System.identityHashCode(domainFile);
	}

	/**
	 * Set this node to be deleted so that it can be
	 * rendered as such.
	 */
	@Override
	public void setIsCut(boolean isCut) {
		this.isCut = isCut;
		fireNodeChanged(getParent(), this);
	}

	/**
	 * Returns whether this node is marked as deleted.
	 */
	@Override
	public boolean isCut() {
		return isCut;
	}

	@Override
	public boolean isEditable() {
		return domainFile.isInWritableProject();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (isCut) {
			return disabledIcon;
		}
		return icon;
	}

	@Override
	public String getName() {
		return domainFile.getName();
	}

	/**
	 * Set the name of this node; update the associated file or folder.
	 */
	void setName(String newName) {
		try {
			domainFile.setName(newName);
		}
		catch (Exception e) {
			Msg.showError(this, null, "Set Name Failed", e.getMessage());
		}
	}

	/**
	 * Get the name to display in tree.
	 */
	@Override
	public String getDisplayText() {
		return displayName;
	}

	private class DomainFileNodeSwingWorker extends SwingWorker<DomainFileNode, Object> {

		@Override
		protected DomainFileNode doInBackground() throws Exception {
			doRefresh();
			return DomainFileNode.this;
		}
	}

	/**
	 * Update the display name.
	 * @return true if the node should be reloaded because the
	 * display name has changed
	 */
	void refresh() {
		DomainFileNodeSwingWorker worker = new DomainFileNodeSwingWorker();
		worker.execute();
	}

	private void doRefresh() {

		//DomainFolderNode parent = (DomainFolderNode) getParent();

		String name = domainFile.getName();
		//domainFile = parent.getDomainFolder().getFile(name);

		String newDisplayName = name;

		if (domainFile.isHijacked()) {
			newDisplayName += " (hijacked)";
		}
		else if (domainFile.isVersioned()) {
			int versionNumber = domainFile.getVersion();
			String versionStr = "" + versionNumber;

			if (versionNumber < 0) {
				versionStr = "?";
			}

			if (domainFile.isCheckedOut()) {
				int latestVersionNumber = domainFile.getLatestVersion();
				String latestVersionStr = "" + latestVersionNumber;
				if (latestVersionNumber < 0) {
					latestVersionStr = "?";
				}
				newDisplayName += " (" + versionStr + " of " + latestVersionStr + ")";
				if (domainFile.modifiedSinceCheckout()) {
					newDisplayName += "*";
				}
			}
			else {
				newDisplayName += " (" + versionStr + ")";
			}
		}
		displayName = newDisplayName;

		setToolTipText();

		icon = domainFile.getIcon(false);
		disabledIcon = ResourceManager.getDisabledIcon(icon);

		fireNodeChanged(getParent(), this);
	}

	private void setToolTipText() {
		String newToolTipText = toolTipText;
		if (domainFile.isInWritableProject() && domainFile.isHijacked()) {
			newToolTipText = "Hijacked file should be deleted or renamed";
		}
		else {
			long lastModified = domainFile.getLastModifiedTime();
			newToolTipText = "Last Modified " + formatter.format(new Date(lastModified));
			if (domainFile.isCheckedOut()) {
				try {
					ItemCheckoutStatus status = domainFile.getCheckoutStatus();
					if (status != null) {
						newToolTipText = HTMLUtilities.toHTML(
							"Checked out " + formatter.format(new Date(status.getCheckoutTime())) +
								";\n" + newToolTipText);
					}
				}
				catch (IOException e) {
					// just ignore and use the previously set tooltip
				}
			}

			if (domainFile.isReadOnly()) {
				newToolTipText += " (read only)";
			}
		}
		toolTipText = newToolTipText;
	}

	@Override
	public String getToolTip() {
		return toolTipText;
	}

	@Override
	public int compareTo(GTreeNode node) {
		if (node instanceof DomainFolderNode) {
			return 1;
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
				domainFile.setName((String) newValue);
			}
			catch (InvalidNameException | DuplicateFileException e) {
				Msg.showError(this, getTree(), "Rename Failed", "Invalid name: " + e.getMessage());
			}
			catch (IOException e) {
				Msg.showError(this, getTree(), "Rename Failed",
					"There was a problem renaming the file:\n" + e.getMessage(), e);
			}
		}
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return getName();
	}

}
