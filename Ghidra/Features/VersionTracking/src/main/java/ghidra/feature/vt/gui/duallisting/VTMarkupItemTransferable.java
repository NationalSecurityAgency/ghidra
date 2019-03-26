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
package ghidra.feature.vt.gui.duallisting;

import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.program.model.data.DataTypeTransferable;
import ghidra.util.Msg;

import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import docking.dnd.GenericDataFlavor;

class VTMarkupItemTransferable implements Transferable {

	static DataFlavor localMarkupItemFlavor = createLocalMarkupItemFlavor();

	private static DataFlavor createLocalMarkupItemFlavor() {
		try {
			return new GenericDataFlavor(DataFlavor.javaJVMLocalObjectMimeType +
				"; class=ghidra.feature.vt.api.main.VTMarkupItem", "Local markup item object");
		}
		catch (Exception e) {
			Msg.showError(DataTypeTransferable.class, null, null, null, e);
		}
		return null;
	}

	private static DataFlavor[] flavors = { localMarkupItemFlavor };

	private static List<DataFlavor> flavorList = Arrays.asList(flavors);
	private VTMarkupItem markupItem;

	/**
	 * VTMarkupItemTransferable is used when performing drag-n-drop between the source 
	 * and destination within the version tracking dual listing panel.
	 * @param markupItem the mark-up item being dragged and dropped.
	 */
	VTMarkupItemTransferable(VTMarkupItem markupItem) {
		this.markupItem = markupItem;
	}

	/**
	 * Return the transfer data with the given data flavor.
	 */
	@Override
	public synchronized Object getTransferData(DataFlavor f) throws UnsupportedFlavorException,
			IOException {

		if (f.equals(localMarkupItemFlavor)) {
			return markupItem;
		}
		throw new UnsupportedFlavorException(f);

	}

	/**
	 * Return all data flavors that this class supports.
	 */
	@Override
	public synchronized DataFlavor[] getTransferDataFlavors() {
		return flavors;
	}

	/**
	 * Return whether the specified data flavor is supported.
	 */
	@Override
	public boolean isDataFlavorSupported(DataFlavor f) {
		return flavorList.contains(f);
	}
}
