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

import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.*;

import javax.swing.tree.TreePath;

import docking.dnd.GClipboard;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeNodeTransferable;
import ghidra.util.Msg;

/**
 * Manages Ghidra integration with the system clipboard when doing cut/copy/paste
 * operations on domainFiles and domainFolders in a data tree widget.
 * <p>
 */
public class DataTreeClipboardUtils {
	/**
	 * Static instance of a callback handler that is notified when the clipboard is changed
	 * and our data is discarded.
	 */
	private static final ClipboardOwner DATATREE_CLIPBOARD_OWNER =
		(clipboard, contents) -> clearCuttables(contents);

	/**
	 * Pushes the GTreeNodes in the specified TreePath array to the clipboard.
	 * 
	 * @param tree DataTree that contains the GTreeNodes
	 * @param paths array of TreePaths containing nodes to be pushed to clipboard.
	 */
	public static void setClipboardContents(DataTree tree, TreePath[] paths) {
		clearCuttables();

		Clipboard clipboard = GClipboard.getSystemClipboard();
		List<GTreeNode> list = new ArrayList<>();
		for (TreePath element : paths) {
			GTreeNode node = (GTreeNode) element.getLastPathComponent();
			list.add(node);
		}

		GTreeNodeTransferable contents =
			new GTreeNodeTransferable(tree.getDragNDropHandler(), list);

		try {
			clipboard.setContents(contents, DATATREE_CLIPBOARD_OWNER);
		}
		catch (IllegalStateException ise) {
			// this can happen when other applications are accessing the system clipboard
			Msg.showError(DataTreeClipboardUtils.class, tree, "Unable to Access Clipboard",
				"Unable to perform cut/copy operation on the system clipboard.  The " +
					"clipboard may just be busy at this time. Please try again.");
		}
	}

	/**
	 * Clears the {@link Cuttable#isCut() isCut} flag on any GTreeNodes that are pointed to by
	 * the system clipboard. 
	 */
	public static void clearCuttables() {
		clearCuttables(getSystemClipboardTransferable());
	}

	/**
	 * Clears the {@link Cuttable#isCut() isCut} flag on any GTreeNodes that are pointed to by
	 * the specified {@link Transferable} 
	 *  
	 * @param transferable contains clipboard contents
	 */
	public static void clearCuttables(Transferable transferable) {
		for (GTreeNode node : getDataTreeNodesFromClipboard(transferable)) {
			if (node instanceof Cuttable) {
				((Cuttable) node).setIsCut(false);
			}
		}
	}

	/**
	 * Returns true if the system clipboard has any GTreeNodes that have the {@link Cuttable#isCut()}
	 * flag set.
	 * 
	 * @return boolean true if there are any cut nodes in the clipboard
	 */
	public static boolean isCuttablePresent() {
		for (GTreeNode node : getDataTreeNodesFromClipboard()) {
			if (node instanceof Cuttable) {
				return ((Cuttable) node).isCut();
			}
		}
		return false;
	}

	/**
	 * Fetches any GTreeNodes from the system clipboard.
	 * 
	 * @return List of {@link GTreeNode}s that were in the system clipboard, or empty list if
	 * no nodes or some other access error.
	 */
	public static List<GTreeNode> getDataTreeNodesFromClipboard() {
		Transferable transferable = getSystemClipboardTransferable();
		return getDataTreeNodesFromClipboard(transferable);
	}

	private static List<GTreeNode> getDataTreeNodesFromClipboard(Transferable transferable) {
		if (transferable != null && transferable.isDataFlavorSupported(
			DataTreeDragNDropHandler.localDomainFileTreeFlavor)) {

			try {
				@SuppressWarnings("unchecked")
				List<GTreeNode> list = (List<GTreeNode>) transferable.getTransferData(
					DataTreeDragNDropHandler.localDomainFileTreeFlavor);
				if (list != null) {
					return list;
				}
			}
			catch (UnsupportedFlavorException | IOException e) {
				Msg.debug(DataTreeClipboardUtils.class, "Failed retrieve tree nodes from clipboard",
					e);
			}
		}
		return Collections.emptyList();
	}

	private static Transferable getSystemClipboardTransferable() {
		try {
			return GClipboard.getSystemClipboard().getContents(
				DataTreeClipboardUtils.class /* not used */);
		}
		catch (Exception ise) {
			// This can happen when the system clipboard is 'busy'.
			// Ignore, as this is just to fixup action enablement
		}
		return null;
	}

}
