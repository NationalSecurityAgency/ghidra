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
package ghidra.app.plugin.core.programtree;

import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.*;

import docking.dnd.GenericDataFlavor;

/**
 * Defines data that is available for drag/drop and clipboard transfers.
 * The data is an ArrayList of ProgramNode objects. 
 */
class ProgramTreeTransferable implements Transferable, ClipboardOwner {

	public static DataFlavor localTreeNodeFlavor = createLocalTreeNodeFlavor();

	// create a data flavor that is an ArrayList of ProgramNode objects
	private static DataFlavor createLocalTreeNodeFlavor() {
		return new GenericDataFlavor(
			DataFlavor.javaJVMLocalObjectMimeType + "; class=java.util.ArrayList",
			"Local list of Tree Nodes");
	}

	private static DataFlavor[] flavors = { localTreeNodeFlavor };

	private static List<DataFlavor> flavorList = Arrays.asList(flavors);
	private List<ProgramNode> nodeList;

	ProgramTreeTransferable(ProgramNode[] nodes) {
		nodeList = new ArrayList<ProgramNode>(Arrays.asList(nodes));
	}

	@Override
	public synchronized DataFlavor[] getTransferDataFlavors() {
		return flavors;
	}

	@Override
	public boolean isDataFlavorSupported(DataFlavor f) {
		return flavorList.contains(f);
	}

	@Override
	public synchronized Object getTransferData(DataFlavor f)
			throws UnsupportedFlavorException, IOException {

		if (f.equals(localTreeNodeFlavor)) {
			return nodeList;
		}
		throw new UnsupportedFlavorException(f);
	}

	@Override
	public String toString() {
		return "TreeTransferable";
	}

	@Override
	public void lostOwnership(Clipboard clipboard, Transferable contents) {
		// nothing to do
	}

	void clearTransferData() {
		nodeList = null;
	}
}
