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
package ghidra.app.plugin.core.function.editor;

import ghidra.program.model.data.*;

class DataTypeManagerStub extends StandAloneDataTypeManager {

	protected DataTypeManagerStub(String name) {
		super(name);
		populate();
	}

	/**
	 * Add the built in data types to the default built in folder if they
	 * were not found in any other category.
	 */
	protected void populate() {
		int id = super.startTransaction("Populate");
		try {
			resolve(new ByteDataType(), null);
			resolve(new CharDataType(), null);
			resolve(new BooleanDataType(), null);
			resolve(new DoubleDataType(), null);
			resolve(new StringDataType(), null);
			resolve(new Undefined1DataType(), null);
			resolve(new Undefined2DataType(), null);
			resolve(new Undefined4DataType(), null);
			resolve(new Undefined8DataType(), null);
			resolve(new UnicodeDataType(), null);
			resolve(new VoidDataType(), null);
			resolve(new IntegerDataType(), null);
			resolve(new ShortDataType(), null);

			StructureDataType struct1 = new StructureDataType("abc", 4);
			struct1.setCategoryPath(new CategoryPath("/foo"));
			resolve(struct1, null);

			StructureDataType struct2 = new StructureDataType("abc", 4);
			struct2.setCategoryPath(new CategoryPath("/bar"));
			resolve(struct2, null);
		}
		finally {
			super.endTransaction(id, true);
		}

	}

}
