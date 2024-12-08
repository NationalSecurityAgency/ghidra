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
package ghidra.program.model.lang;

import java.util.ArrayList;

import ghidra.program.model.data.DataType;

/**
 * Raw components of a function prototype (obtained from parsing source code)
 */
public class PrototypePieces {
	public PrototypeModel model;			// (Optional) model on which prototype is based
//	public String name;						// Identifier (function name) associated with prototype
	public DataType outtype;				// Return data-type
	public ArrayList<DataType> intypes;		// Input data-types
//	public ArrayList<String> innames;		// Identifiers for input types
	public int firstVarArgSlot;				// First position of a variable argument, or -1 if not vararg

	/**
	 * Populate pieces from old-style array of DataTypes
	 * @param model is the prototype model
	 * @param oldList is the list of output and input data-types
	 * @param injectedThis if non-null is the data-type of the this pointer to be injected
	 */
	public PrototypePieces(PrototypeModel model, DataType[] oldList, DataType injectedThis) {
		this.model = model;
		outtype = oldList[0];
		intypes = new ArrayList<>();
		firstVarArgSlot = -1;
		if (injectedThis != null) {
			intypes.add(injectedThis);
		}
		for (int i = 1; i < oldList.length; ++i) {
			intypes.add(oldList[i]);
		}
	}

	/**
	 * Create prototype with output data-type and empty/unspecified input data-types
	 * @param model is the prototype model
	 * @param outType is the output data-type
	 */
	public PrototypePieces(PrototypeModel model, DataType outType) {
		this.model = model;
		outtype = outType;
		intypes = new ArrayList<>();
		firstVarArgSlot = -1;
	}
}
