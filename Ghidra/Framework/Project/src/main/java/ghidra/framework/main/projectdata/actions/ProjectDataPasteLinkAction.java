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
import ghidra.framework.data.LinkHandler;
import ghidra.framework.main.datatable.ProjectTreeAction;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;
import resources.MultiIcon;

public class ProjectDataPasteLinkAction extends ProjectTreeAction {
	private static Icon baseIcon = Icons.PASTE_ICON;

	public ProjectDataPasteLinkAction(String owner, String group) {
		super("Paste Link", owner);
		setPopupMenuData(new MenuData(new String[] { "Paste as Link" }, getIcon(), group));
		setHelpLocation(new HelpLocation("FrontEndPlugin", "Create_File_Links"));
	}

	private static Icon getIcon() {
		MultiIcon multiIcon = new MultiIcon(baseIcon);
		multiIcon.addIcon(LinkHandler.LINK_ICON);
		return multiIcon;
	}

	@Override
	protected void actionPerformed(FrontEndProjectTreeContext context) {
		GTreeNode node = (GTreeNode) context.getContextObject();
		DomainFolderNode destNode = getFolderForNode(node);
		if (!isEnabledForContext(context)) {
			Msg.showWarn(getClass(), context.getTree(), "Unsupported Operation",
				"Unsupported paste link condition");
		}

		GTreeNode copyNode = getFolderOrFileCopyNode();
		if (copyNode instanceof DomainFileNode) {
			try {
				DomainFile domainFile = ((DomainFileNode) copyNode).getDomainFile();
				domainFile.copyToAsLink(destNode.getDomainFolder());
			}
			catch (IOException e) {
				Msg.showError(getClass(), context.getTree(), "Cannot Create Link",
					"Error occured while creating link file", e);
			}
		}
		else {
			try {
				DomainFolder domainFolder = ((DomainFolderNode) copyNode).getDomainFolder();
				domainFolder.copyToAsLink(destNode.getDomainFolder());
			}
			catch (IOException e) {
				Msg.showError(getClass(), context.getTree(), "Cannot Create Link",
					"Error occured while creating link file", e);
			}
		}

	}

	@Override
	protected boolean isEnabledForContext(FrontEndProjectTreeContext context) {
		if (!context.hasExactlyOneFileOrFolder()) {
			return false;
		}
		if (!context.isInActiveProject()) {
			return false;
		}
		GTreeNode node = (GTreeNode) context.getContextObject();
		DomainFolderNode destNode = getFolderForNode(node);

		GTreeNode copyNode = getFolderOrFileCopyNode();
		if (copyNode == null || copyNode.getParent() == null) {
			return false;
		}

		// local internal linking not supported
		if (destNode.getRoot() == copyNode.getRoot()) {
			return false;
		}

		if (copyNode instanceof DomainFileNode) {
			DomainFile df = ((DomainFileNode) copyNode).getDomainFile();
			return df.isLinkingSupported();
		}
		return true;
	}

	@Override
	protected boolean isAddToPopup(FrontEndProjectTreeContext context) {
		if (!context.hasOneOrMoreFilesAndFolders()) {
			return false;
		}
		if (!context.isInActiveProject()) {
			return false;
		}
		GTreeNode copyNode = getFolderOrFileCopyNode();
		return copyNode != null && copyNode.getParent() != null;
	}

	private DomainFolderNode getFolderForNode(GTreeNode node) {
		if (node instanceof DomainFolderNode) {
			return (DomainFolderNode) node;
		}
		return (DomainFolderNode) node.getParent();
	}

	private GTreeNode getFolderOrFileCopyNode() {
		List<GTreeNode> list = DataTreeClipboardUtils.getDataTreeNodesFromClipboard();
		if (list.size() != 1) {
			return null;
		}
		GTreeNode copyNode = list.get(0);
		if (copyNode instanceof DomainFileNode) {
			if (!((DomainFileNode) copyNode).isCut()) {
				return copyNode;
			}
		}
		if (copyNode instanceof DomainFolderNode) {
			if (!((DomainFolderNode) copyNode).isCut()) {
				return copyNode;
			}
		}
		return null;
	}

}
