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

import ghidra.program.model.listing.Group;
import ghidra.util.Msg;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * A test implementation of data that could be dragged onto the ProgramTree.
 */
public class GroupTransferable implements Transferable {
    
    public static DataFlavor localGroupFlavor = createLocalGroupFlavor();
    
    private Group group;
    private String name;
    
    private static DataFlavor createLocalGroupFlavor() {
        try {
            return new DataFlavor(
                DataFlavor.javaJVMLocalObjectMimeType+
                "; class="+Group.class.getName(), 
                "Local Group");
            
        }catch (Exception e) {
            Msg.showError(GroupTransferable.class, null, null, null, e);
        }
        return null;
    }
    private static DataFlavor []flavors= 
        {localGroupFlavor, DataFlavor.stringFlavor};
    
    private static List<DataFlavor> flavorList = Arrays.asList(flavors);
    
    
    /**
     * Constructor
     */
    public GroupTransferable(Group g) {
        group = g;
    }
    public GroupTransferable(String name) {
        
        this.name = name;
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
            
        if (f.equals(localGroupFlavor)) {
            return group;
        }
        if (f.equals(DataFlavor.stringFlavor)) {
            return name;
        }
        throw new UnsupportedFlavorException(f);
        
    }
    @Override
    public String toString() {
        return "GroupTransferable";
    }
    
}
