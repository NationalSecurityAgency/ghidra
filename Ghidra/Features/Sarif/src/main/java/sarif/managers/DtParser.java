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
package sarif.managers;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.CancelledException;

/**
 * DtParser
 */
class DtParser {

	private DataTypeParser parser;

	DtParser(DataTypeManager dtManager) {
		this.parser = new DataTypeParser(dtManager, dtManager, null, AllowedDataTypes.DYNAMIC);
	}

	/**
	 * Parse the specified dtName within the specified category.
	 * @param dtName
	 * @param category
	 * @param size optional root-type size, or -1 for unspecified
	 * @return root-type if found, or null if not found
	 */
	DataType parseDataType(String dtName, CategoryPath category, int size) {
		DataType dt;
		try {
			dt = parser.parse(dtName, category);
		}
		catch (InvalidDataTypeException | CancelledException e) {
			return null;
		}
		return dt;
	}

}
