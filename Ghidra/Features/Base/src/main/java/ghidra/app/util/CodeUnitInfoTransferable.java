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

import ghidra.util.Msg;

import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import docking.dnd.GenericDataFlavor;

/**
 * Defines data that is available for drag/drop and clipboard transfers.
 * The data is an ArrayList of CodeUnitInfo objects.
 */
public class CodeUnitInfoTransferable implements Transferable, ClipboardOwner {

	/**
	 * DataFlavor that it is an ArrayList of CodeUnitInfo objects.
	 */
	public static DataFlavor localDataTypeFlavor = createLocalDataTypeFlavor();

	private static DataFlavor createLocalDataTypeFlavor() {

		try {
			return new GenericDataFlavor(DataFlavor.javaJVMLocalObjectMimeType +
				"; class=java.util.ArrayList", "Local code unit info object");
		}
		catch (Exception e) {
			Msg.showError(CodeUnitInfoTransferable.class, null, "Could Not Create Data Flavor",
				"Unexpected exception creating data flavor for code unit info", e);
		}

		return null;
	}

	private static DataFlavor[] flavors = { localDataTypeFlavor /*, textDataTypeFlavor*/};

	private static List<DataFlavor> flavorList = Arrays.asList(flavors);
	private List<CodeUnitInfo> infoList;

	/**
	 * Construct a new CodeUnitTransferable.
	 * @param list list of CodeUnitInfo objects
	 */
	public CodeUnitInfoTransferable(List<CodeUnitInfo> list) {
		infoList = list;
	}

	/**
	 * Return all data flavors that this class supports.
	 */
	public synchronized DataFlavor[] getTransferDataFlavors() {
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
	public synchronized Object getTransferData(DataFlavor f) throws UnsupportedFlavorException,
			IOException {

		if (f.equals(localDataTypeFlavor)) {
			return infoList;
		}
		throw new UnsupportedFlavorException(f);
	}

	/**
	 * Get the string representation for this transferable.
	 */
	@Override
	public String toString() {
		return "CodeUnitInfoTransferable";
	}

	/*
	 *  (non-Javadoc)
	 * @see java.awt.datatransfer.ClipboardOwner#lostOwnership(java.awt.datatransfer.Clipboard, java.awt.datatransfer.Transferable)
	 */
	public void lostOwnership(Clipboard clipboard, Transferable contents) {
	}

}
