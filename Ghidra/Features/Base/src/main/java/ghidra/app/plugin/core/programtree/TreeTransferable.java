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
package ghidra.app.plugin.core.programtree;

import ghidra.util.Msg;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import docking.dnd.GenericDataFlavor;

/**
 * Defines data that is available for drag/drop and clipboard transfers.
 * The data is an ArrayList of ProgramNode objects. 
 */
class TreeTransferable implements Transferable, ClipboardOwner {
    
    public static DataFlavor localTreeNodeFlavor = createLocalTreeNodeFlavor();
    
    // create a data flavor that is an ArrayList of 
    // ProgramNode objects
    private static DataFlavor createLocalTreeNodeFlavor() {
        try {
            return new GenericDataFlavor(
                DataFlavor.javaJVMLocalObjectMimeType+
                "; class=java.util.ArrayList", 
                "Local list of Tree Nodes");
        }catch (Exception e) {
            Msg.showError(TreeTransferable.class, null, null, null, e);
        }
        return null;
    }
    private static DataFlavor []flavors= { localTreeNodeFlavor };
    
    private static List<DataFlavor> flavorList = Arrays.asList(flavors);
    private ArrayList<ProgramNode> nodeList;
    
    /**
     * Constructor
     */
    TreeTransferable(ProgramNode []nodes) {
        nodeList = new ArrayList<ProgramNode>(Arrays.asList(nodes));
    }
    
    /**
     * Return all data flavors that this class supports.
     */
    public synchronized DataFlavor []getTransferDataFlavors() {
        return flavors;
    }
    
    /**
     * Return whether the specified data flavor is supported.
     */
    public boolean isDataFlavorSupported(DataFlavor f) {
        return flavorList.contains(f);
    }
    
    /**
     * Return the transfer data with the given data flavor.
     */
    public synchronized Object getTransferData(DataFlavor f) 
        throws UnsupportedFlavorException, IOException {
            
        if (f.equals(localTreeNodeFlavor)) {
            return nodeList;
        }
        throw new UnsupportedFlavorException(f);
        
    }
	/**
	 * Get the string representation for this transferable.
	 */
    @Override
    public String toString() {
        return "TreeTransferable";
    }
    
    /**
     * ClipboardOwner interface method.
     */
    public void lostOwnership(Clipboard clipboard, Transferable contents) {
    }
    
    void clearTransferData() {
        nodeList = null;
    }
}
