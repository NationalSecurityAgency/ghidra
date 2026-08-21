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
package ghidra.file.crypto;

import java.io.IOException;
import java.util.List;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTreeNode;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.plugins.fsbrowser.*;

public class CryptoKeysFSBFileHandler implements FSBFileHandler {

	private FSBFileHandlerContext context;

	@Override
	public void init(FSBFileHandlerContext context) {
		this.context = context;
	}

	@Override
	public List<DockingAction> createActions() {
		return List
				.of(new ActionBuilder("FSB Create Crypto Key Template", context.plugin().getName())
						.withContext(FSBActionContext.class)
						.enabledWhen(ac -> ac.notBusy() &&
							ac.getSelectedNode() instanceof FSBRootNode && ac.getFSRL(true) != null)
						.popupMenuPath("Create Crypto Key Template...")
						.popupMenuGroup("Z", "B")
						.onAction(ac -> {
							FSRL fsrl = ac.getFSRL(true);
							if (ac.getSelectedNode() instanceof FSBRootNode rootNode &&
								fsrl != null) {
								createCryptoTemplate(fsrl, rootNode);
							}
						})
						.build());
	}

	/**
	 * Creates a crypto key file template based on the specified files under the GTree node.
	 *
	 * @param fsrl FSRL of a child file of the container that the crypto will be associated with
	 * @param node GTree node with children that will be iterated
	 */
	private void createCryptoTemplate(FSRL fsrl, FSBRootNode node) {
		try {
			String fsContainerName = fsrl.getFS().getContainer().getName();
			CryptoKeyFileTemplateWriter writer = new CryptoKeyFileTemplateWriter(fsContainerName);
			if (writer.exists()) {
				int answer =
					OptionDialog.showYesNoDialog(null, "WARNING!! Crypto Key File Already Exists",
						"WARNING!!" + "\n" + "The crypto key file already exists. " +
							"Are you really sure that you want to overwrite it?");
				if (answer == OptionDialog.NO_OPTION) {
					return;
				}
			}
			writer.open();
			try {
				// gTree.expandAll( node );
				writeFile(writer, node.getChildren());
			}
			finally {
				writer.close();
			}
		}
		catch (IOException e) {
			FSUtilities.displayException(this, null, "Error writing crypt key file", e.getMessage(),
				e);
		}

	}

	private void writeFile(CryptoKeyFileTemplateWriter writer, List<GTreeNode> children)
			throws IOException {

		if (children == null || children.isEmpty()) {
			return;
		}
		for (GTreeNode child : children) {
			if (child instanceof FSBFileNode fileNode) {
				FSRL childFSRL = fileNode.getFSRL();
				writer.write(childFSRL.getName());
			}
			else {
				writeFile(writer, child.getChildren());
			}
		}
	}

}
