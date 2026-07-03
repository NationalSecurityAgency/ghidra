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
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;

/**
 * Provides an implementation of a byte that has not been defined yet as a
 * particular type of data in the program.
 */
public class DefaultDataType extends DataTypeImpl {

	/** A statically defined DefaultDataType used when an Undefined byte is needed.*/
	public static DefaultDataType dataType = new DefaultDataType();

	private DefaultDataType() {
		super(CategoryPath.ROOT, "undefined", null);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "??";
	}

	@Override
	public int getLength() {
		return 1;
	}

	@Override
	public String getDescription() {
		return "Undefined Byte";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		try {
			int b = buf.getByte(0) & 0xff;
			String rep = Integer.toHexString(b).toUpperCase() + "h";
			if (rep.length() == 2) {
				rep = "0" + rep;
			}
			if (b > 31 && b < 128) {
				rep += "    " + ((char) b);
			}
			return rep;
		}
		catch (MemoryAccessException e) {
			return "??";
		}
	}

	/**
	 * Get the Undefined byte as a Scalar.
	 *
	 * @param buf the data buffer.
	 * @param settings the display settings to use.
	 * @param length the number of bytes to get the value from.
	 * @return the data Object.
	 */
	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		try {
			return new Scalar(8, buf.getByte(0));
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Scalar.class;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		return this;
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		return this;
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		return dt == this;
	}

	@Override
	public void addParent(DataType dt) {
		// this datatype is STATIC, don't hold on to parents
	}

	@Override
	public void removeParent(DataType dt) {
		// this datatype is STATIC, don't hold on to parents
	}

	@Override
	public long getLastChangeTime() {
		return NO_SOURCE_SYNC_TIME;
	}

}
