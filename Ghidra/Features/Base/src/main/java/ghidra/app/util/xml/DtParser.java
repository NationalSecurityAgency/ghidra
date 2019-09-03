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
package ghidra.app.util.xml;

import ghidra.program.model.data.*;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.CancelledException;

/**
 * DtParser
 */
class DtParser {

	private DataTypeManager dtManager;
	private DataTypeParser parser;

	DtParser(DataTypeManager dtManager) {
		this.dtManager = dtManager;
		this.parser = new DataTypeParser(dtManager, dtManager, null, AllowedDataTypes.DYNAMIC);
	}

	/**
	 * Parse the specified dtName within the specified category.
	 * @param dtName
	 * @param category
	 * @param size optional data-type size, or -1 for unspecified
	 * @return data-type if found, or null if not found
	 */
	DataType parseDataType(String dtName, CategoryPath category, int size) {
		DataType dt;
		try {
			dt = parser.parse(dtName, category);
		}
		catch (InvalidDataTypeException | CancelledException e) {
			return null;
		}
		if (size > 0 && size != dt.getLength()) {
			dt = adjustPointerDataTypes(size, dt);
		}
		return dt;
	}

	/**
	 * Adjust pointer data-types based upon specified size which may not be 
	 * factored into pointer specification (e.g., void *32).
	 * @param size
	 * @param dt
	 * @return adjusted data-type
	 */
	private DataType adjustPointerDataTypes(int size, DataType dt) {
		if (dt instanceof Pointer) {
			Pointer p = (Pointer) dt;
			dt = new PointerDataType(p.getDataType(), size, dtManager);
		}
		else if (dt instanceof Array && ((Array) dt).getDataType() instanceof Pointer) {
// TODO: does not handle multi-dimensional pointer arrays
			Array array = (Array) dt;
			DataType pointerDt = ((Pointer) array.getDataType()).getDataType();
			int pointerSize = size / array.getNumElements();
			DataType pointer = new PointerDataType(pointerDt, pointerSize, dtManager);
			dt = new ArrayDataType(pointer, array.getNumElements(), pointerSize, dtManager);
		}
		return dt;
	}
}
