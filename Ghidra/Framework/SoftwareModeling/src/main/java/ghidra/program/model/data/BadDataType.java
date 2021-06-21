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

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.classfinder.ClassSearcher;

/**
 * Provides an implementation of a data type that is not valid (bad) as it is used in
 * the program. For example, the class for the underlying data type may no longer be 
 * available or the data type may not fit where it has been placed in the program.
 *  <P> 
 *  This field is not meant to be loaded by the {@link ClassSearcher}, hence the X in the name.
 */
public class BadDataType extends BuiltIn implements Dynamic {
	private final static long serialVersionUID = 1;

	public static final BadDataType dataType = new BadDataType();

	public BadDataType() {
		this(null);
	}

	public BadDataType(DataTypeManager dtm) {
		super(null, "-BAD-", dtm);
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getMnemonic(Settings)
	 */
	@Override
	public String getMnemonic(Settings settings) {
		return getName();
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	@Override
	public int getLength() {
		return -1;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	@Override
	public String getDescription() {
		return "** Bad Data Type **";
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return getDescription();
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		return dt instanceof BadDataType;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getRepresentation(MemBuffer, Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return getDescription();
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new BadDataType(dtm);
	}

	@Override
	public boolean canSpecifyLength() {
		return true;
	}

	@Override
	public int getLength(MemBuffer buf, int maxLength) {
		return -1;
	}

	@Override
	public DataType getReplacementBaseType() {
		return null;
	}

}
