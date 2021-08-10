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
package ghidra.program.database.data;

import ghidra.program.model.data.DataType;

/**
 * <code>DataTypeProxyComponentDB</code> facilitates a datatype/component substitution when a 
 * DataTypeManagerDB is constructed for read-only use and datatype migration is required.  
 * An example of this is the {@link StructureDB} migration of flex-arrays to a zero-element array.
 */
class DataTypeProxyComponentDB extends DataTypeComponentDB {

	private final String fieldName;
	private final String comment;

	/**
	 * Construct a DataTypeComponentDB with specific component characteristics and without a record.
	 * @param dataMgr associated datatype manager
	 * @param parent composite datatype which contains this component
	 * @param ordinal component ordinal
	 * @param offset component offset
	 * @param length component length
	 * @param datatype component datatype
	 * @param fieldName component field name or null
	 * @param comment component comment or null
	 */
	DataTypeProxyComponentDB(DataTypeManagerDB dataMgr, CompositeDB parent, int ordinal, int offset,
			DataType datatype, int length, String fieldName, String comment) {
		super(dataMgr, parent, ordinal, offset, datatype, length);
		this.fieldName = fieldName;
		this.comment = comment;
	}

	@Override
	public String getFieldName() {
		return fieldName;
	}

	@Override
	public String getComment() {
		return comment;
	}
}
