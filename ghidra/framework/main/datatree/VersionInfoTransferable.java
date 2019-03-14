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
package ghidra.framework.main.datatree;

import ghidra.util.Msg;

import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import docking.dnd.GenericDataFlavor;

/**
 * Defines a transferable 
 */
public class VersionInfoTransferable implements Transferable, ClipboardOwner {
    
	/**
	 * DataFlavor for VersionInfoTransferable.
	 */
    public static DataFlavor localVersionInfoFlavor = createLocalVersionInfoFlavor();
    
    // create a data flavor that is a path to a domain file and a version
    // number
    private static DataFlavor createLocalVersionInfoFlavor() {
        try {
            return new GenericDataFlavor(
                DataFlavor.javaJVMLocalObjectMimeType+
                "; class="+ "\"" + VersionInfo.class.getName() + "\"",
                "Local DomainFile Version object");
        }catch (Exception e) {
            Msg.showError(VersionInfoTransferable.class, null, null, null, e);
        }
        return null;
    }

    private static DataFlavor []flavors= 
        {localVersionInfoFlavor};
    
    private static List<DataFlavor> flavorList = Arrays.asList(flavors);

	private VersionInfo versionInfo;
	
	
	VersionInfoTransferable(String domainFilePath, int version) {
		versionInfo = new VersionInfo(domainFilePath, version);
	}
		
	/* (non-Javadoc)
	 * @see java.awt.datatransfer.Transferable#getTransferDataFlavors()
	 */
	public DataFlavor[] getTransferDataFlavors() {
		return flavors;
	}

	/* (non-Javadoc)
	 * @see java.awt.datatransfer.Transferable#isDataFlavorSupported(java.awt.datatransfer.DataFlavor)
	 */
	public boolean isDataFlavorSupported(DataFlavor flavor) {
		return flavorList.contains(flavor);
	}

	/* (non-Javadoc)
	 * @see java.awt.datatransfer.Transferable#getTransferData(java.awt.datatransfer.DataFlavor)
	 */
	public Object getTransferData(DataFlavor flavor)
		throws UnsupportedFlavorException, IOException {
        if (flavor.equals(localVersionInfoFlavor)) {
            return versionInfo;
        }
        throw new UnsupportedFlavorException(flavor);
	}

	/* (non-Javadoc)
	 * @see java.awt.datatransfer.ClipboardOwner#lostOwnership(java.awt.datatransfer.Clipboard, java.awt.datatransfer.Transferable)
	 */
	public void lostOwnership(Clipboard clipboard, Transferable contents) {
	}
	/**
	 * Get the string representation for this transferable.
	 */
    @Override
	public String toString() {
        return "VersionInfoTransferable";
    }
    

}
