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
package ghidra.framework.main.projectdata.actions;

import java.io.IOException;
import java.util.List;

import javax.swing.Icon;

import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.data.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.datatable.ProjectTreeAction;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;
import resources.MultiIcon;

public class ProjectDataPasteLinkAction extends ProjectTreeAction {
	private static Icon baseIcon = Icons.PASTE_ICON;

	private boolean relative;

	public ProjectDataPasteLinkAction(String owner, String group, boolean relative) {
		super("Paste " + getLinkType(relative), owner);
		this.relative = relative;
		setPopupMenuData(
			new MenuData(new String[] { "Paste as " + getLinkType(relative) }, getIcon(), group));
		setHelpLocation(new HelpLocation("FrontEndPlugin", "Paste_Link"));
	}

	private static String getLinkType(boolean relative) {
		return relative ? "Relative-Link" : "Link";
	}

	private static Icon getIcon() {
		MultiIcon multiIcon = new MultiIcon(baseIcon);
		multiIcon.addIcon(LinkHandler.LINK_ICON);
		return multiIcon;
	}

	@Override
	protected void actionPerformed(FrontEndProjectTreeContext context) {
		if (!isEnabledForContext(context)) {
			return;
		}

		GTreeNode node = (GTreeNode) context.getContextObject();
		DomainFolder destFolder = DataTree.getRealInternalFolderForNode(node);
		if (destFolder == null) {
			Msg.showWarn(getClass(), context.getTree(), "Unsupported Operation",
				"Unsupported paste link condition");
		}

		GTreeNode copyNode = getFolderOrFileCopyNode();
		if (copyNode instanceof DomainFileNode fileNode) {
			try {
				DomainFile domainFile = fileNode.getDomainFile();
				domainFile.copyToAsLink(destFolder, relative);
			}
			catch (IOException e) {
				Msg.showError(getClass(), context.getTree(), "Cannot Create Link",
					"Error occured while creating link file", e);
			}
		}
		else {
			try {
				DomainFolder domainFolder = ((DomainFolderNode) copyNode).getDomainFolder();
				domainFolder.copyToAsLink(destFolder, relative);
			}
			catch (IOException e) {
				Msg.showError(getClass(), context.getTree(), "Cannot Create Link",
					"Error occured while creating link file", e);
			}
		}

	}

	@Override
	protected boolean isEnabledForContext(FrontEndProjectTreeContext context) {
		if (!context.isInActiveProject() || !context.hasExactlyOneFileOrFolder()) {
			return false;
		}
		GTreeNode node = (GTreeNode) context.getContextObject();
		DomainFolder destFolder = DataTree.getRealInternalFolderForNode(node);
		if (!ProjectDataPasteAction.checkNodeForPaste(destFolder)) {
			return false;
		}
		Project activeProject = AppInfo.getActiveProject();
		DataTreeNode copyNode = getFolderOrFileCopyNode();
		if (copyNode != null) {
			if (relative && copyNode.getProjectData() != activeProject.getProjectData()) {
				return false;
			}
			if (copyNode instanceof DomainFileNode fileNode) {
				// Only enable action if a LinkHandler exists for the file
				DomainFile domainFile = fileNode.getDomainFile();
				try {
					ContentHandler<?> contentHandler =
						DomainObjectAdapter.getContentHandler(domainFile.getContentType());
					return contentHandler.getLinkHandler() != null;
				}
				catch (IOException e) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

	private DataTreeNode getFolderOrFileCopyNode() {
		// Null will be returned if single node is marked for cut operation
		List<GTreeNode> list = DataTreeClipboardUtils.getDataTreeNodesFromClipboard();
		if (list.size() != 1) {
			return null;
		}
		GTreeNode copyNode = list.get(0);
		if (copyNode instanceof DomainFileNode fileNode) {
			if (!fileNode.isCut()) {
				return fileNode;
			}
		}
		if (copyNode instanceof DomainFolderNode folderNode) {
			if (!folderNode.isCut()) {
				return folderNode;
			}
		}
		return null;
	}

}
