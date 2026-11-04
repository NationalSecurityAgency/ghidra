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
package ghidra.app.plugin.core.symboltree;

import java.awt.datatransfer.*;
import java.awt.dnd.DnDConstants;
import java.io.IOException;
import java.util.*;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeDragNDropHandler;
import ghidra.app.plugin.core.symboltree.nodes.*;
import ghidra.app.plugin.core.symtable.dnd.SymbolDataFlavor;
import ghidra.app.plugin.core.symtable.dnd.SymbolTransferData;
import ghidra.app.util.SelectionTransferData;
import ghidra.app.util.SelectionTransferable;
import ghidra.program.database.symbol.MemorySymbol;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;

/**
 * A drag and drop handler for the {@link SymbolTreePlugin}.  There is limited support for dragging
 * nodes within the tree to move symbols.  This class also supports the dragging of symbol nodes 
 * into transient symbol tables.
 */
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
		if (destinationNode instanceof NamespaceSymbolNode namespaceNode) {
			doDropOnNamespace(namespaceNode, transferable);
		}
		else if (destinationNode instanceof LibrarySymbolNode libraryNode) {
			doDropOnLibrary(libraryNode, transferable);
		}
		else if (destinationNode instanceof GlobalsCategoryNode) {
			doDropOnGlobal(transferable);
		}

	}

	private void doDropOnGlobal(Transferable transferable) {

		List<Symbol> symbols = getSymbolTreeSymbols(transferable);
		Namespace global = plugin.getProgram().getGlobalNamespace();
		SymbolTreeProvider provider = plugin.getProvider();
		provider.reparentSymbols(global, symbols);	// set to global namespace
	}

	private void doDropOnLibrary(LibrarySymbolNode libraryNode, Transferable transferable) {
		Library library = libraryNode.getLibrary();
		List<Symbol> symbols = getSymbolTreeSymbols(transferable);
		List<MemorySymbol> memorySymbols = new ArrayList<>();
		for (Symbol symbol : symbols) {
			// MemorySymbol has the method for setting a library and only external symbols can
			// be in a library.
			if (!(symbol instanceof MemorySymbol memorySymbol) || !symbol.isExternal()) {
				Msg.showError(this, null, "Drop Failed",
					"Only external function or label symbols can be dropped on a Library: " +
						symbol.getName());
				return;
			}
			memorySymbols.add(memorySymbol);
		}
		SymbolTreeProvider provider = plugin.getProvider();
		provider.setLibrary(library, memorySymbols);
	}

	private void doDropOnNamespace(NamespaceSymbolNode destination, Transferable transferable) {
		Namespace namespace = destination.getNamespace();
		if (transferable.isDataFlavorSupported(SelectionTransferable.localProgramSelectionFlavor)) {
			SelectionTransferData selectionData = getSelectionTransferData(transferable);
			dropProgramSelection(namespace, selectionData);
		}
		else {
			List<Symbol> symbolsToMoveList = getSymbolTreeSymbols(transferable);
			SymbolTreeProvider provider = plugin.getProvider();
			int count = provider.reparentSymbols(namespace, symbolsToMoveList);
			if (count != symbolsToMoveList.size()) {
				plugin.getTool().setStatusInfo("Failed to move one more specified symbols");
			}
		}
	}

	private SelectionTransferData getSelectionTransferData(Transferable transferable) {
		try {
			Object transferData =
				transferable.getTransferData(SelectionTransferable.localProgramSelectionFlavor);
			return (SelectionTransferData) transferData;
		}
		catch (UnsupportedFlavorException e) {
			Msg.showError(this, plugin.getTool().getToolFrame(), "Unsupported Data Flavor",
				"Unable to handle dropping of given data flavor: " + e.getMessage());
		}
		catch (IOException e) {
			Msg.showError(this, plugin.getTool().getToolFrame(), "Unexpected Exception",
				"Unable to handle dropping of given data", e);
		}
		return null;
	}

	private void dropProgramSelection(Namespace namespace, SelectionTransferData selectionData) {
		if (selectionData == null) {
			return;
		}
		List<Symbol> symbolsToMove = new ArrayList<>();
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

	private List<Symbol> getSymbolTreeSymbols(Transferable transferable) {
		List<Symbol> symbols = new ArrayList<>();
		try {
			Object transferData = transferable.getTransferData(SymbolTreeDataFlavor.DATA_FLAVOR);
			@SuppressWarnings("unchecked")
			List<GTreeNode> nodeList = (List<GTreeNode>) transferData;
			for (GTreeNode node : nodeList) {
				if (node instanceof SymbolNode symbolNode) {
					symbols.add(symbolNode.getSymbol());
				}
			}
		}
		catch (UnsupportedFlavorException | IOException e) {
			Msg.showError(this, plugin.getTool().getToolFrame(), "Unexpected Exception",
				"Unable to handle dropping of given data", e);
		}
		return symbols;
	}

	@Override
	public int getSupportedDragActions() {
		return DnDConstants.ACTION_MOVE;
	}

	@Override
	public boolean isDropSiteOk(GTreeNode destinationUserNode, DataFlavor[] flavors,
			int dropAction) {

		if (dropAction != DnDConstants.ACTION_MOVE) {
			return false;
		}

		Program program = plugin.getProgram();
		if (program == null || program.isClosed()) {
			return false;
		}
		if (destinationUserNode instanceof GlobalsCategoryNode) {
			return true;
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
		if (dragUserData.isEmpty()) {
			return false;
		}
		for (GTreeNode node : dragUserData) {
			if (!(node instanceof SymbolNode)) {
				return false;
			}
			if (node instanceof LibrarySymbolNode) {
				return false;
			}
		}
		return true;
	}

	@Override
	public DataFlavor[] getSupportedDataFlavors(List<GTreeNode> transferNodes) {
		Set<DataFlavor> flavorSet = new HashSet<>();
		for (GTreeNode node : transferNodes) {
			SymbolTreeNode symbolNode = (SymbolTreeNode) node;
			DataFlavor flavor = symbolNode.getNodeDataFlavor();
			if (flavor != null) {
				flavorSet.add(flavor);
			}

			if (symbolNode instanceof SymbolNode) {
				flavorSet.add(SymbolDataFlavor.DATA_FLAVOR);
			}
		}
		return flavorSet.toArray(new DataFlavor[flavorSet.size()]);
	}

	@Override
	public Object getTransferData(List<GTreeNode> transferNodes, DataFlavor flavor)
			throws UnsupportedFlavorException {

		if (SymbolDataFlavor.DATA_FLAVOR.equals(flavor)) {
			return getSymbolTransferData(transferNodes);
		}
		/*
			The generic flavor for the Symbol Tree.  This is used to paste all nodes in the list.
			These nodes will be given to the Symbol Tree provider, which will decide how to process
			each node.
		
			Note: symbolNode.getNodeDataFlavor() is used to get the flavor of each node being 
		      	transfered.  But, we do not use those flavors to process the nodes on a drop().
		      	Instead, we use the generic SymbolTreeDataFlavor.DATA_FLAVOR and let the provider
		      	handle each node separately. (see getSupportedDataFlavors() in this file) 
		 */
		else if (SymbolTreeDataFlavor.DATA_FLAVOR.equals(flavor)) {
			List<GTreeNode> nodes = new ArrayList<>();
			for (GTreeNode node : transferNodes) {
				SymbolTreeNode symbolNode = (SymbolTreeNode) node;
				nodes.add(symbolNode);
			}
			return nodes;
		}

		throw new UnsupportedFlavorException(flavor);
	}

	private SymbolTransferData getSymbolTransferData(List<GTreeNode> transferNodes) {
		List<Symbol> symbols = new ArrayList<>();
		for (GTreeNode node : transferNodes) {
			if (node instanceof SymbolNode symbolNode) {
				symbols.add(symbolNode.getSymbol());
			}
		}

		SymbolTreeProvider provider = plugin.getProvider();
		GTree tree = provider.getTree();
		return new SymbolTransferData(tree, symbols);
	}

}
