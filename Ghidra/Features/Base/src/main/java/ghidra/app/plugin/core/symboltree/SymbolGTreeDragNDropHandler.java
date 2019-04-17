/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.symboltree;

import ghidra.app.plugin.core.symboltree.nodes.*;
import ghidra.app.util.SelectionTransferData;
import ghidra.app.util.SelectionTransferable;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;

import java.awt.datatransfer.*;
import java.awt.dnd.DnDConstants;
import java.io.IOException;
import java.util.*;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeDragNDropHandler;

public class SymbolGTreeDragNDropHandler implements GTreeDragNDropHandler {

	private final SymbolTreePlugin plugin;

	SymbolGTreeDragNDropHandler(SymbolTreePlugin plugin) {
		this.plugin = plugin;
	}

	@Override
	public void drop(GTreeNode destinationNode, Transferable transferable, int dropAction) {
		if (dropAction != DnDConstants.ACTION_MOVE) {
			return;
		}

		if (!(destinationNode instanceof SymbolTreeNode)) {
			return;
		}

		SymbolTreeNode destinationSymbolNode = (SymbolTreeNode) destinationNode;
		Namespace namespace = destinationSymbolNode.getNamespace();
		if (namespace == null) {
			return;
		}

		if (transferable.isDataFlavorSupported(SelectionTransferable.localProgramSelectionFlavor)) {
			try {
				Object transferData =
					transferable.getTransferData(SelectionTransferable.localProgramSelectionFlavor);
				SelectionTransferData selectionData = (SelectionTransferData) transferData;
				dropProgramSelection(namespace, selectionData);
				return;
			}
			catch (UnsupportedFlavorException e) {
				Msg.showError(this, plugin.getTool().getToolFrame(), "Unsupported Data Flavor",
					"Unable to handle dropping of given data flavor: " + e.getMessage());
			}
			catch (IOException e) {
				Msg.showError(this, plugin.getTool().getToolFrame(), "Unexpected Exception",
					"Unable to handle dropping of given data", e);
			}
		}

		try {
			Object transferData = transferable.getTransferData(SymbolTreeDataFlavor.DATA_FLAVOR);
			if (transferData instanceof List<?>) {
				dropNodeList(namespace, transferData);
				return;
			}
		}
		catch (UnsupportedFlavorException e) {
			Msg.showError(this, plugin.getTool().getToolFrame(), "Unsupported Data Flavor",
				"Unable to handle dropping of given data flavor: " + e.getMessage());
		}
		catch (IOException e) {
			Msg.showError(this, plugin.getTool().getToolFrame(), "Unexpected Exception",
				"Unable to handle dropping of given data", e);
		}

	}

	private void dropProgramSelection(Namespace namespace, SelectionTransferData selectionData) {
		List<Symbol> symbolsToMove = new ArrayList<Symbol>();
		Program program = plugin.getProgram();
		FunctionManager functionManager = program.getFunctionManager();
		AddressSetView addressSet = selectionData.getAddressSet();
		FunctionIterator iterator = functionManager.getFunctions(addressSet, true);
		for (Function function : iterator) {
			symbolsToMove.add(function.getSymbol());
		}

		SymbolTreeProvider provider = plugin.getProvider();
		if (provider.reparentSymbols(namespace, symbolsToMove) != symbolsToMove.size()) {
			plugin.getTool().setStatusInfo("Failed to move one more specified symbols");
		}
	}

	private void dropNodeList(Namespace namespace, Object transferData) {
		@SuppressWarnings("unchecked")
		List<GTreeNode> nodeList = (List<GTreeNode>) transferData;
		List<Symbol> symbolsToMoveList = new ArrayList<Symbol>();
		for (GTreeNode node : nodeList) {
			// we only allow dragging of SymbolNodes
			SymbolNode symbolNode = (SymbolNode) node;
			Symbol symbol = symbolNode.getSymbol();
			symbolsToMoveList.add(symbol);
		}

		SymbolTreeProvider provider = plugin.getProvider();
		if (provider.reparentSymbols(namespace, symbolsToMoveList) != symbolsToMoveList.size()) {
			plugin.getTool().setStatusInfo("Failed to move one more specified symbols");
		}
	}

	@Override
	public int getSupportedDragActions() {
		return DnDConstants.ACTION_MOVE;
	}

	@Override
	public boolean isDropSiteOk(GTreeNode destinationUserNode, DataFlavor[] flavors, int dropAction) {
		if (dropAction != DnDConstants.ACTION_MOVE) {
			return false;
		}

		Program program = plugin.getProgram();
		if (program == null || program.isClosed()) {
			return false;
		}

		if (!(destinationUserNode instanceof SymbolTreeNode)) {
			return false;
		}

		SymbolTreeNode node = (SymbolTreeNode) destinationUserNode;
		return node.supportsDataFlavors(flavors);
	}

	@Override
	public boolean isStartDragOk(List<GTreeNode> dragUserData, int dragAction) {
		if (dragAction != DnDConstants.ACTION_MOVE) {
			return false;
		}

		for (GTreeNode node : dragUserData) {
			SymbolTreeNode symbolNode = (SymbolTreeNode) node;
			DataFlavor dataFlavor = symbolNode.getNodeDataFlavor();
			if (dataFlavor == null) {
				return false;
			}
		}

		return dragUserData.size() != 0;
	}

	@Override
	public DataFlavor[] getSupportedDataFlavors(List<GTreeNode> transferNodes) {
		Set<DataFlavor> flavorSet = new HashSet<DataFlavor>();
		for (GTreeNode node : transferNodes) {
			SymbolTreeNode symbolNode = (SymbolTreeNode) node;
			DataFlavor flavor = symbolNode.getNodeDataFlavor();
			if (flavor != null) {
				flavorSet.add(flavor);
			}
		}
		return flavorSet.toArray(new DataFlavor[flavorSet.size()]);
	}

	@Override
	public Object getTransferData(List<GTreeNode> transferNodes, DataFlavor flavor)
			throws UnsupportedFlavorException {
		return transferNodes;
	}

}
