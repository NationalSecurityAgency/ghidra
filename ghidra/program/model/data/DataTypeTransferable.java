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
package ghidra.program.model.data;

import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import docking.dnd.GenericDataFlavor;
import ghidra.util.Msg;

/**
 * Defines data that is available for drag/drop and clipboard transfers.
 * The data is a DataType object.
 */
public class DataTypeTransferable implements Transferable, ClipboardOwner {

	// Flavor for this Transferable
	public static final DataFlavor localDataTypeFlavor = createLocalDataTypeFlavor();
	public static final DataFlavor localBuiltinDataTypeFlavor = createLocalBuiltinDataTypeFlavor();

	// create a data flavor that is a tool button
	private static DataFlavor createLocalDataTypeFlavor() {
		try {
			return new GenericDataFlavor(DataFlavor.javaJVMLocalObjectMimeType +
				"; class=ghidra.program.model.data.DataTypeImpl", "Local data type object");
		}
		catch (Exception e) {
			Msg.showError(DataTypeTransferable.class, null, null, null, e);
		}
		return null;
	}

	private static DataFlavor createLocalBuiltinDataTypeFlavor() {
		try {
			return new GenericDataFlavor(DataFlavor.javaJVMLocalObjectMimeType +
				"; class=ghidra.program.model.data.DataTypeImpl", "Local BuiltIn data type object");
		}
		catch (Exception e) {
			Msg.showError(DataTypeTransferable.class, null, null, null, e);
		}
		return null;
	}

	private static DataFlavor[] flavors = { localDataTypeFlavor, localBuiltinDataTypeFlavor };

	private static List<DataFlavor> flavorList = Arrays.asList(flavors);
	private DataType dataType;

	/**
	 * Constructor
	 * @param dt the dataType being transfered
	 */
	public DataTypeTransferable(DataType dt) {
		dataType = dt;
	}

	/**
	 * Return all data flavors that this class supports.
	 */
	@Override
	public synchronized DataFlavor[] getTransferDataFlavors() {
		return flavors;
	}

	/**
	 * Return whether the specifed data flavor is supported.
	 */
	@Override
	public boolean isDataFlavorSupported(DataFlavor f) {
		return flavorList.contains(f);
	}

	/**
	 * Return the transfer data with the given data flavor.
	 */
	@Override
	public synchronized Object getTransferData(DataFlavor f) throws UnsupportedFlavorException,
			IOException {

		if (f.equals(localDataTypeFlavor) || f.equals(localBuiltinDataTypeFlavor)) {
			return dataType;
		}
		throw new UnsupportedFlavorException(f);

	}

	/**
	 * Get the string representation for this transferable.
	 */
	@Override
	public String toString() {
		return "DataTypeTransferable";
	}

	/**
	 * ClipboardOwner interface method.
	 */
	@Override
	public void lostOwnership(Clipboard clipboard, Transferable contents) {
	}

}
