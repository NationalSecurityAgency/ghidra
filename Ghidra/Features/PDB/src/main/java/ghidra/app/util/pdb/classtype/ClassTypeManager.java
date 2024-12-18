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
package ghidra.app.util.pdb.classtype;

import ghidra.app.util.SymbolPath;
import ghidra.program.model.data.*;

/**
 * Class Type Manager
 */
public class ClassTypeManager {

	private static final String CLASS_TYPE_MANAGER_PROTOTYPE2 = "CLASS_TYPE_MANAGER_PROTOTYPE2";

	private DataTypeManager dtm;

	private PointerDataType defaultPtrType;
	private PointerDataType defaultVbtPtr;
	private PointerDataType defaultVftPtr;

	/**
	 * Constructor
	 * @param dtm the data type manager
	 */
	public ClassTypeManager(DataTypeManager dtm) {
		this.dtm = dtm;

		defaultPtrType = new PointerDataType(dtm);
		defaultVbtPtr = new PointerDataType(new IntegerDataType(dtm));
		defaultVftPtr = new PointerDataType(new PointerDataType(dtm));
	}

	public SymbolPath getSymbolPath(ClassID classId) {
		if (classId instanceof ProgramClassID gId) {
			return gId.getSymbolPath();
		}
		return null;
	}

	/**
	 * Returns the underlying data type manager
	 * @return the data type manager
	 */
	public DataTypeManager getDataTypeManager() {
		return dtm;
	}

	/**
	 * Returns the default pointer type
	 * @return the pointer type
	 */
	public PointerDataType getDefaultPointerType() {
		return defaultPtrType;
	}

	/**
	 * Returns the default virtual base table pointer type
	 * @return the pointer type
	 */
	public PointerDataType getDefaultVbtPtr() {
		return defaultVbtPtr;
	}

	/**
	 * Returns the default virtual function table pointer type
	 * @return the pointer type
	 */
	public PointerDataType getDefaultVftPtr() {
		return defaultVftPtr;
	}

	/**
	 * Returns the default size of a virtual base table entry
	 * @return the size of the entry
	 */
	public int getDefaultVbtTableElementSize() {
		return dtm.getDataOrganization().getIntegerSize();
	}

	/**
	 * Returns the default size of a virtual function table entry
	 * @return the size of the entry
	 */
	public int getDefaultVftTableElementSize() {
		return dtm.getDataOrganization().getPointerSize();
	}

}
