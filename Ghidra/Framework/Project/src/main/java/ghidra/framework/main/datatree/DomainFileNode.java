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
import java.net.MalformedURLException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.Icon;
import javax.swing.SwingWorker;

import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.framework.data.LinkHandler;
import ghidra.framework.data.LinkHandler.LinkStatus;
import ghidra.framework.main.BrokenLinkIcon;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.TaskMonitor;

/**
 * Class to represent a node in the Data tree.
 */
public class DomainFileNode extends DataTreeNode {

	private static final Icon UNKNOWN_FILE_ICON = new GIcon("icon.datatree.node.domain.file");
	private static final String RIGHT_ARROW = Character.isDefined(0x2192) ? "\u2192" : "->";

	private final DomainFile domainFile;

	private volatile String displayName; // name displayed in the tree
	private volatile Icon icon = UNKNOWN_FILE_ICON;
	private volatile Icon cutIcon;
	private volatile String toolTipText;
	private AtomicInteger refreshCount = new AtomicInteger();

	private boolean isLeaf = true;
	private LinkFileInfo linkInfo;
	private DomainFileFilter filter; // relavent when expand folder-link which is a file

	private static final SimpleDateFormat formatter = new SimpleDateFormat("yyyy MMM dd hh:mm aaa");

	DomainFileNode(DomainFile domainFile, DomainFileFilter filter) {
		this.domainFile = domainFile;
		this.linkInfo = domainFile.getLinkInfo();
		this.filter = filter != null ? filter : DomainFileFilter.ALL_FILES_FILTER;
		displayName = domainFile.getName();
		refresh();
	}

	@Override
	public boolean isAutoExpandPermitted() {
		// Prevent auto-expansion through linked-folders
		return false;
	}

	/**
	 * Get the domain file if this node represents a file object versus a folder; interface method
	 * for DomainDataTransfer.
	 * 
	 * @return null if this node represents a domain folder
	 */
	public DomainFile getDomainFile() {
		return domainFile;
	}

	@Override
	public boolean isLeaf() {
		return isLeaf;
	}

	@Override
	public int getChildCount() {
		if (isLeaf) {
			// Optimization to avoid repeated attempts at following a bad link
			return 0;
		}
		return super.getChildCount();
	}

	/**
	 * Determine if this file node corresponds to a folder-link
	 * @return true if file is a folder-link
	 */
	public boolean isFolderLink() {
		if (linkInfo != null) {
			return linkInfo.isFolderLink();
		}
		return false;
	}

	/**
	 * Get linked folder which corresponds to this folder-link
	 * (see {@link #isFolderLink()}).
	 * @return linked folder or null if this is not a folder-link
	 */
	LinkedDomainFolder getLinkedFolder() {
		if (!isLeaf() && linkInfo != null) { // verifies that we are allowed to follow based upon filter
			return linkInfo.getLinkedFolder();
		}
		return null;
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
		if (domainFile.equals(node.domainFile)) {
			return true;
		}
		return false;
	}

	@Override
	public int hashCode() {
		return domainFile.hashCode();
	}

	@Override
	public boolean isEditable() {
		return domainFile.isInWritableProject();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (isCut()) {
			return cutIcon;
		}
		return icon;
	}

	@Override
	public String getName() {
		return domainFile.getName();
	}

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
			try {
				doRefresh();
			}
			finally {
				refreshCount.decrementAndGet();
			}
			return DomainFileNode.this;
		}
	}

	/**
	 * {@return true if a pending refresh exists for this node}
	 * This method intended for test use only.
	 */
	public boolean hasPendingRefresh() {
		return refreshCount.get() != 0;
	}

	/**
	 * Update the display name.
	 */
	void refresh() {
		refreshCount.incrementAndGet();
		DomainFileNodeSwingWorker worker = new DomainFileNodeSwingWorker();
		worker.execute();
	}

	private void doRefresh() {

		isLeaf = true;
		linkInfo = null;

		boolean brokenLink = false;
		List<String> linkErrors = null;
		if (domainFile.isLink()) {
			linkInfo = domainFile.getLinkInfo();
			List<String> errors = new ArrayList<>();
			LinkStatus linkStatus =
				LinkHandler.getLinkFileStatus(domainFile, msg -> errors.add(msg));
			brokenLink = (linkStatus == LinkStatus.BROKEN);
			if (brokenLink) {
				linkErrors = errors;
			}
			else if (isFolderLink()) {
				if (linkStatus == LinkStatus.INTERNAL) {
					isLeaf = false;
				}
				else if (linkStatus == LinkStatus.EXTERNAL &&
					filter.followExternallyLinkedFolders()) {
					isLeaf = false;
				}
			}
		}

		if (isLeaf) {
			unloadChildren();
		}

		displayName = getFormattedDisplayName();

		toolTipText = HTMLUtilities.toLiteralHTMLForTooltip(getToolTipText(domainFile, linkErrors));

		refreshIcons(brokenLink);

		fireNodeChanged();
	}

	private String getFormattedDisplayName() {

		String newDisplayName = domainFile.getName();
		if (domainFile.isHijacked()) {
			newDisplayName += " (hijacked)";
		}
		else if (domainFile.isVersioned() && !domainFile.isLink()) {
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

		if (domainFile.isLink()) {
			newDisplayName += " " + RIGHT_ARROW + " " + getFormattedLinkPath();
		}
		return newDisplayName;
	}

	private String getFormattedLinkPath() {

		String linkPath = linkInfo != null ? linkInfo.getLinkPath() : null;
		if (GhidraURL.isGhidraURL(linkPath)) {
			try {
				URL url = new URL(linkPath);
				if (GhidraURL.isLocalGhidraURL(linkPath)) {
					ProjectLocator loc = GhidraURL.getProjectStorageLocator(url);
					if (loc != null) {
						String projectPath = GhidraURL.getProjectPathname(url);
						linkPath = loc.getName() + ":" + projectPath;
					}
				}
				else if (GhidraURL.isServerURL(linkPath)) {
					String host = url.getHost();
					String repo = GhidraURL.getRepositoryName(url);
					if (repo != null) {
						String projectPath = GhidraURL.getProjectPathname(url);
						linkPath = host + "[" + repo + "]:" + projectPath;
					}
				}
			}
			catch (MalformedURLException e) {
				// ignore - use original linkPath
			}
		}
		return linkPath;
	}

	private void refreshIcons(boolean isBrokenLink) {

		icon = domainFile.getIcon(false);
		cutIcon = domainFile.getIcon(true);
		if (isBrokenLink) {
			icon = new BrokenLinkIcon(icon);
			cutIcon = new BrokenLinkIcon(cutIcon);
		}
	}

	public static String getToolTipText(DomainFile domainFile, List<String> linkErrors) {
		StringBuilder buf = new StringBuilder();
		if (domainFile.isInWritableProject() && domainFile.isHijacked()) {
			buf.append("Hijacked file should be deleted or renamed");
		}

		if (linkErrors != null) {
			linkErrors.forEach(linkError -> appendLine(buf, linkError));
		}

		if (domainFile.isCheckedOut()) {
			try {
				ItemCheckoutStatus status = domainFile.getCheckoutStatus();
				if (status != null) {
					appendLine(buf,
						"Checked out " + formatter.format(new Date(status.getCheckoutTime())));
				}
			}
			catch (IOException e) {
				// just ignore and use the previously set tooltip
			}
		}

		long lastModified = domainFile.getLastModifiedTime();
		appendLine(buf, "Last Modified " + formatter.format(new Date(lastModified)));

		if (domainFile.isReadOnly()) {
			appendLine(buf, "(read only)");
		}
		return buf.toString();
	}

	private static void appendLine(StringBuilder buf, String line) {
		if (!buf.isEmpty()) {
			buf.append('\n');
		}
		buf.append(line);
	}

	@Override
	public String getToolTip() {
		return toolTipText;
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

	@Override
	public String toString() {
		return getName();
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		if (isLeaf || linkInfo == null) {
			return List.of();
		}
		return generateChildren(linkInfo.getLinkedFolder(), filter, monitor);
	}

	@Override
	public GTreeNode getChild(String name, NodeType type) {
		return getChild(children(), name, type);
	}

	@Override
	public ProjectData getProjectData() {
		return domainFile.getParent().getProjectData();
	}

}
