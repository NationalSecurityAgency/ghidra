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
package ghidra.app.util;

import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import docking.dnd.GenericDataFlavor;

import ghidra.util.Msg;

/**
 * Defines data that is available for drag/drop and clipboard transfers.
 * The data is an AddressSetView.
 */
public class SelectionTransferable implements Transferable, ClipboardOwner {
    
	/**
	 * DataFlavor for program selection.
	 */
    public static DataFlavor localProgramSelectionFlavor = createLocalProgramSelectionFlavor(); 
    
    // create a data flavor that is an AddressSetView and a program pathname
    private static DataFlavor createLocalProgramSelectionFlavor() {
        try {
            // note: The class specified cannot be an interface,
            // contrary to what the javadocs specify.
            return new GenericDataFlavor(
                DataFlavor.javaJVMLocalObjectMimeType+
                "; class="+ SelectionTransferData.class.getName(),
                "Local Transfer Data for Program Selections");
        }catch (Exception e) {
            Msg.showError(SelectionTransferable.class, null, null, null, e);
        }
        return null;
    }
    private static DataFlavor []flavors= 
        {localProgramSelectionFlavor};
    
    private static List<DataFlavor> flavorList = Arrays.asList(flavors);
    private SelectionTransferData selectionData;
    
    /**
     * Construct a new SelectionTransferable.
     * @param selectionData the data indicating the selection for the selection transferable
     */
    public SelectionTransferable(SelectionTransferData selectionData) {
    	this.selectionData = selectionData;
    }
    
    /**
     * Return all data flavors that this class supports.
     */
    public synchronized DataFlavor []getTransferDataFlavors() {
        return flavors;
    }
    
    /**
     * Return whether the specifed data flavor is supported.
     */
    public boolean isDataFlavorSupported(DataFlavor f) {
        return flavorList.contains(f);
    }

    /**
     * Return the transfer data with the given data flavor.
     */
    public synchronized Object getTransferData(DataFlavor f) 
        throws UnsupportedFlavorException, IOException {
            
        if (f.equals(localProgramSelectionFlavor)) {
            return selectionData;
        }
        throw new UnsupportedFlavorException(f);
        
    }
    /*
     *  (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "SelectionTransferable";
    }
 
    /*
     *  (non-Javadoc)
     * @see java.awt.datatransfer.ClipboardOwner#lostOwnership(java.awt.datatransfer.Clipboard, java.awt.datatransfer.Transferable)
     */
    public void lostOwnership(Clipboard clipboard, Transferable contents) {
    }
    
}
