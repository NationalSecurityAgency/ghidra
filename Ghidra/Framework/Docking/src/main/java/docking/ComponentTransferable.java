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
package docking;

import java.awt.datatransfer.*;
import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.util.Msg;

/**
 * Defines data that is available for drag/drop and clipboard transfers.
 * The data is a CompProv object which is just a holder for a owner and name for a component.
 */
class ComponentTransferable implements Transferable, ClipboardOwner {
	private static final Logger LOGGER = LogManager.getLogger(ComponentTransferable.class);
    
	public static DataFlavor localComponentProviderFlavor = createLocalComponentProviderFlavor();
    
	// create a data flavor that is a tool button
	private static DataFlavor createLocalComponentProviderFlavor() {
		try {
			return new DataFlavor(ComponentTransferableData.class, "Component Provider");
		}catch (Exception e) {
		    Msg.error(LOGGER, "Unexpected Exception: " + e.getMessage(), e);
		}
		return null;
	}
	
	private static DataFlavor []flavors= 
		{localComponentProviderFlavor};
    
	private ComponentTransferableData provider;
    
	/**
	 * Constructs a new ComponentTransferable with the given CompProv object.
	 */
	ComponentTransferable(ComponentTransferableData provider) {
		this.provider = provider;
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
		return f == localComponentProviderFlavor;
	}
    
	/**
	 * Return the transfer data with the given data flavor.
	 */
	public synchronized Object getTransferData(DataFlavor f) 
		throws UnsupportedFlavorException, IOException {
            
		if (f.equals(localComponentProviderFlavor)) {
			return provider;
		}
		throw new UnsupportedFlavorException(f);
        
	}
	/**
	 * Get the string representation for this transferable.
	 */
	@Override
    public String toString() {
		return "ComponentProviderTransferable";
	}
    
	/**
	 * ClipboardOwner interface method.
	 */
	public void lostOwnership(Clipboard clipboard, Transferable contents) {
	}

	/**
	 * Clear the tool button that is being transferred.
	 */
	void clearTransferData() {
		provider = null;
	}
}
