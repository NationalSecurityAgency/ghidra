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
package docking.widgets.tree.support;

import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.List;

import docking.widgets.tree.GTreeNode;

/**
 * A transferable for sharing data via drag/drop and clipboard operations for GTrees.
 */
public class GTreeNodeTransferable implements Transferable {
    private final List<GTreeNode> selectedData;
    private final GTreeTransferHandler transferHandler;

    /**
     * Creates this transferable based upon the selected data and uses the given transfer
     * handler to perform {@link Transferable} operations.
     * @param handler the handler used to perform transfer operations.
     * @param selectedData The
     */
    public GTreeNodeTransferable( GTreeTransferHandler handler, List<GTreeNode> selectedData) {
        this.selectedData = selectedData;
        this.transferHandler = handler;
    }

    /**
     * Returns all of the original selected data contained by this transferable.
     * @return all of the original selected data contained by this transferable
     */
    public List<GTreeNode> getAllData() {
        return selectedData;
    }

    /**
     * Gets the transfer data from the selection based upon the given flavor.
     * @param transferNodes The nodes from which to get the data.
     * @param flavor The flavor of data to retreive from the given selection.
     * @return the transfer data from the selection based upon the given flavor.
     * @throws UnsupportedFlavorException if the given flavor is not one of the supported flavors
     * returned by {@link #getSupportedDataFlavors(List)}.
     */
    public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException, IOException {
        return transferHandler.getTransferData(selectedData, flavor);
    }

    /**
	 * Returns the DataFlavors for the types of data that this transferable supports, based upon
	 * the given selection.
	 * @param transferNodes The nodes to base the DataFlavor selection upon.
	 * @return the DataFlavors for the types of data that this transferable supports, based upon
	 * the given selection.
	 */
    public DataFlavor[] getTransferDataFlavors() {
        return transferHandler.getSupportedDataFlavors(selectedData);
    }

    /**
     * A convenience method to determine if this transferable supports the given flavor.
     * @return true if this transferable supports the given flavor.
     */
    public boolean isDataFlavorSupported(DataFlavor flavor) {
        DataFlavor[] flavors = transferHandler.getSupportedDataFlavors(selectedData);
        for(int i=0;i<flavors.length;i++) {
            if (flavors[i].equals(flavor)) {
                return true;
            }
        }
        return false;
    }
}
