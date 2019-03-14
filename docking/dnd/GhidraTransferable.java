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
package docking.dnd;

import ghidra.util.Msg;

import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.*;


public class GhidraTransferable implements Transferable, ClipboardOwner {

	/**
	 * A static instance of the local flavor that is an  ArrayList of
	 * user object objects.
	 */
	public static DataFlavor localGhidraFlavor = createLocalGhidraFlavor();

	// create a data flavor that is an ArrayList of
	// user objects
	private static DataFlavor createLocalGhidraFlavor() {
		try {
			return new GenericDataFlavor(
					DataFlavor.javaJVMLocalObjectMimeType+
					"; class=java.util.ArrayList",
			"Local list of Drag/Drop User objects");
		}catch (Exception e) {
			Msg.showError(GhidraTransferable.class, null, null, null, e);
		}
		return null;
	}
	private static DataFlavor []flavors= {localGhidraFlavor};

	private static List<DataFlavor> flavorList = Arrays.asList(flavors);
	private List<Object> dataList;

	/**
	 * Constructs a new Transferable from the array of DragDropNodes
	 * @param dataList the array of DragDropNodes being transfered.
	 */
	public GhidraTransferable(List<?> dataList) {
		this.dataList = new ArrayList<Object>(dataList);
	}

	/**
	 * Return all data flavors that this class supports.
	 */
	public synchronized DataFlavor []getTransferDataFlavors() {
		return flavors;
	}

	/**
	 * Return whether the specifed data flavor is supported.
	 * @param f the DataFlavor to check if supported.
	 */
	public boolean isDataFlavorSupported(DataFlavor f) {
		return flavorList.contains(f);
	}

	/**
	 * Return the transfer data with the given data flavor.
	 * @param f the DataFlavor for which to get a Transferable.
	 */
	public synchronized Object getTransferData(DataFlavor f)
	throws UnsupportedFlavorException, IOException {

		if (f.equals(localGhidraFlavor)) {
			return dataList;
		}
		throw new UnsupportedFlavorException(f);

	}
	/**
	 * Get the string representation for this transferable.
	 */
	@Override
    public String toString() {
		return "GhidraTransferable";
	}

	/**
	 * Notification we have lost ownership of the clipboard because
	 * something else was put on the clipboard.
	 * @param clipboard the system clipboard.
	 * @param contents the Transferable lost in the clipboard.
	 */
	public void lostOwnership(Clipboard clipboard, Transferable contents) {
	}

}
