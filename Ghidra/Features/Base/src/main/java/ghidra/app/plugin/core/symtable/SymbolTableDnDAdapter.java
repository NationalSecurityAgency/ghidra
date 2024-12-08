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
package ghidra.app.plugin.core.symtable;

import java.awt.Component;
import java.awt.Container;
import java.awt.datatransfer.*;
import java.awt.dnd.*;
import java.io.IOException;
import java.util.List;

import docking.widgets.table.RowObjectTableModel;
import ghidra.app.plugin.core.symtable.dnd.SymbolDataFlavor;
import ghidra.app.plugin.core.symtable.dnd.SymbolTransferData;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;

/**
 * A class to combine Symbol drag and drop operations into one class.  Clients will need to 
 * implement methods for getting the selected symbols and then adding dropped symbols.
 */
public abstract class SymbolTableDnDAdapter extends SymbolTableDragProvider
		implements DropTargetListener {

	public SymbolTableDnDAdapter(GhidraTable table, RowObjectTableModel<SymbolRowObject> model) {
		super(table, model);

		int actions = DnDConstants.ACTION_COPY;
		new DropTarget(table, actions, this, true);

		// Add the drop listener to the table's parent so we can drop on the table's blank area		
		Container parent = table.getParent();
		new DropTarget(parent, actions, this, true);
	}

	/**
	 * Called when symbols are dropped onto the component using this adapter.
	 * @param symbols the dropped symbols
	 */
	protected abstract void addSymbols(List<Symbol> symbols);

//=================================================================================================
// DropTargetListener methods
//=================================================================================================	

	@Override
	public void dragEnter(DropTargetDragEvent dtde) {
		dragOver(dtde);
	}

	@Override
	public void dragExit(DropTargetEvent dte) {
		// don't care
	}

	@Override
	public void dragOver(DropTargetDragEvent dtde) {

		Transferable transferable = dtde.getTransferable();
		if (!transferable.isDataFlavorSupported(SymbolDataFlavor.DATA_FLAVOR)) {
			return;
		}

		try {
			SymbolTransferData symbolData =
				(SymbolTransferData) transferable.getTransferData(SymbolDataFlavor.DATA_FLAVOR);

			Component source = symbolData.getSource();
			if (source == table) {
				// don't allow dragging within the same component
				dtde.rejectDrag();
				return;
			}

			// Ghidra tables only support the concept of one program per table.  We can change this
			// in the future if we find a need to mix table rows that use more than one program.
			if (!hasSameProgram(symbolData)) {
				dtde.rejectDrag();
				return;
			}
		}
		catch (UnsupportedFlavorException | IOException e) {
			// shouldn't happen, since we checked the flavor above
			Msg.error(this, "Unable to perform drop operation", e);
		}

		DataFlavor[] dropFlavors = dtde.getCurrentDataFlavors();
		if (!supportsDropFlavor(dropFlavors)) {
			dtde.rejectDrag();
			return;
		}

		dtde.acceptDrag(dtde.getDropAction());
	}

	private boolean hasSameProgram(SymbolTransferData symbolData) {
		List<Symbol> symbols = symbolData.getSymbols();
		Symbol s = symbols.get(0);
		Program p = s.getProgram();
		GhidraTable ghidraTable = (GhidraTable) table;
		Program myProgram = ghidraTable.getProgram();
		return p == myProgram;
	}

	private boolean supportsDropFlavor(DataFlavor[] dropFlavors) {

		for (DataFlavor f : dropFlavors) {
			if (f.equals(SymbolDataFlavor.DATA_FLAVOR)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void drop(DropTargetDropEvent dtde) {
		dtde.acceptDrop(dtde.getDropAction());

		Transferable transferable = dtde.getTransferable();
		try {
			SymbolTransferData symbolData =
				(SymbolTransferData) transferable.getTransferData(SymbolDataFlavor.DATA_FLAVOR);
			List<Symbol> symbols = symbolData.getSymbols();
			addSymbols(symbols);
		}
		catch (UnsupportedFlavorException | IOException e) {
			Msg.error(this, "Unable to perform drop operation", e);
		}

		dtde.dropComplete(true);
	}

	@Override
	public void dropActionChanged(DropTargetDragEvent dtde) {
		// don't care

	}
}
