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
package docking.widgets.tree.support;

import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.List;
import java.util.Objects;

import docking.widgets.tree.GTreeNode;

/**
 * A transferable for sharing data via drag/drop and clipboard operations for GTrees
 */
public class GTreeNodeTransferable implements Transferable {
	private final List<GTreeNode> selectedData;
	private final GTreeTransferHandler transferHandler;

	/**
	 * Creates this transferable based upon the selected data and uses the given transfer
	 * handler to perform {@link Transferable} operations
	 * 
	 * @param handler the handler used to perform transfer operations
	 * @param selectedData The selected tree nodes
	 */
	public GTreeNodeTransferable(GTreeTransferHandler handler, List<GTreeNode> selectedData) {
		this.transferHandler = Objects.requireNonNull(handler);
		this.selectedData = Objects.requireNonNull(selectedData);
	}

	/**
	 * Returns all of the original selected data contained by this transferable.
	 * @return all of the original selected data contained by this transferable
	 */
	public List<GTreeNode> getAllData() {
		return selectedData;
	}

	/**
	 * Gets the transfer data from the selection based upon the given flavor
	
	 * @param flavor The flavor of data to retrieve from the given selection.
	 * @return the transfer data from the selection based upon the given flavor.
	 * @throws UnsupportedFlavorException if the given flavor is not one of the supported flavors
	 * returned by {@link #getTransferDataFlavors()}
	 */
	@Override
	public Object getTransferData(DataFlavor flavor)
			throws UnsupportedFlavorException, IOException {
		return transferHandler.getTransferData(selectedData, flavor);
	}

	/**
	 * Returns the DataFlavors for the types of data that this transferable supports, based upon
	 * the given selection
	 * 
	 * @return the DataFlavors for the types of data that this transferable supports, based upon
	 * the given selection
	 */
	@Override
	public DataFlavor[] getTransferDataFlavors() {
		return transferHandler.getSupportedDataFlavors(selectedData);
	}

	/**
	 * A convenience method to determine if this transferable supports the given flavor
	 * @return true if this transferable supports the given flavor
	 */
	@Override
	public boolean isDataFlavorSupported(DataFlavor flavor) {
		DataFlavor[] flavors = transferHandler.getSupportedDataFlavors(selectedData);
		for (DataFlavor f : flavors) {
			if (f.equals(flavor)) {
				return true;
			}
		}
		return false;
	}
}
