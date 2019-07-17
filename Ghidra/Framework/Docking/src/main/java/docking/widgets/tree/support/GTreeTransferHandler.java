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

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.util.List;

import docking.widgets.tree.GTreeNode;

/**
 * A generic transfer handler used by GTrees to handle transfering drag/drop data and clipboard
 * data.
 */
public interface GTreeTransferHandler {

	/**
	 * Returns the DataFlavors for the types of data that this transferable supports, based upon
	 * the given selection.
	 * @param transferNodes The nodes to base the DataFlavor selection upon.
	 * @return the DataFlavors for the types of data that this transferable supports, based upon
	 * the given selection.
	 */
    public DataFlavor[] getSupportedDataFlavors(List<GTreeNode> transferNodes);

    /**
     * Gets the transfer data from the selection based upon the given flavor.
     * @param transferNodes The nodes from which to get the data.
     * @param flavor The flavor of data to retrieve from the given selection.
     * @return the transfer data from the selection based upon the given flavor.
     * @throws UnsupportedFlavorException if the given flavor is not one of the supported flavors
     * returned by {@link #getSupportedDataFlavors(List)}.
     */
    public Object getTransferData(List<GTreeNode> transferNodes,
        DataFlavor flavor) throws UnsupportedFlavorException;
}
