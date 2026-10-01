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

/**
 * Defines data that is available for drag/drop and clipboard transfers.
 * The data is a DataType object.
 */
public class DataTypeTransferable implements Transferable, ClipboardOwner {

	/**
	 * Used for drag/drop of a single data type
	 */
	public static final DataFlavor localDataTypeFlavor = createLocalDataTypeFlavor();

	/**
	 * Used for drag/drop of a single data type
	 */
	public static final DataFlavor localBuiltinDataTypeFlavor = createLocalBuiltinDataTypeFlavor();

	/**
	 * Used for drag/drop of a multiple data types
	 */
	public static final DataFlavor localDataTypeListFlavor = createLocalDataTypeListFlavor();

	// create a data flavor for a single data type
	private static DataFlavor createLocalDataTypeFlavor() {
		return new GenericDataFlavor(DataFlavor.javaJVMLocalObjectMimeType +
			"; class=ghidra.program.model.data.DataType", "Local data type object");
	}

	// flavor for single built-in data type
	private static DataFlavor createLocalBuiltinDataTypeFlavor() {
		return new GenericDataFlavor(DataFlavor.javaJVMLocalObjectMimeType +
			"; class=ghidra.program.model.data.DataType", "Local BuiltIn data type object");
	}

	// create a data flavor that is a List of data types
	private static DataFlavor createLocalDataTypeListFlavor() {
		return new GenericDataFlavor(
			DataFlavor.javaJVMLocalObjectMimeType + "; class=java.util.List",
			"Local list of Drag/Drop DataType objects");
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

	@Override
	public synchronized DataFlavor[] getTransferDataFlavors() {
		return flavors;
	}

	@Override
	public boolean isDataFlavorSupported(DataFlavor f) {
		return flavorList.contains(f);
	}

	@Override
	public synchronized Object getTransferData(DataFlavor f) throws UnsupportedFlavorException,
			IOException {

		if (f.equals(localDataTypeFlavor) || f.equals(localBuiltinDataTypeFlavor)) {
			return dataType;
		}
		throw new UnsupportedFlavorException(f);

	}

	@Override
	public String toString() {
		return "DataTypeTransferable";
	}

	@Override
	public void lostOwnership(Clipboard clipboard, Transferable contents) {
		// stub
	}

}
