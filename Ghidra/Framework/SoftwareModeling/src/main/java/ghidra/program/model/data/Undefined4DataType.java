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
import ghidra.util.StringFormat;
import ghidra.util.classfinder.*;

/**
 * Provides an implementation of a 4-byte dataType that has not been defined yet as a
 * particular type of data in the program.
 */
public class Undefined4DataType extends Undefined {
	static {
		ClassTranslator.put("ghidra.program.model.data.Undefined4",
			Undefined4DataType.class.getName());
	}

	private final static long serialVersionUID = 1;

	/** A statically defined DefaultDataType used when an Undefined byte is needed.*/
	public final static Undefined4DataType dataType = new Undefined4DataType();

	/**
	 * Cronstructs a new Undefined4 dataType
	 *
	 */
	public Undefined4DataType() {
		this(null);
	}

	public Undefined4DataType(DataTypeManager dtm) {
		super("undefined4", dtm);
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	public int getLength() {
		return 4;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	public String getDescription() {
		return "Undefined Double Word";
	}

	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Undefined4DataType(dtm);
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getMnemonic(Settings)
	 */
	public String getMnemonic(Settings settings) {
		return name;
	}

	private long getValue(MemBuffer buf) throws MemoryAccessException {
		long val = buf.getInt(0);
		return val & 0xffffffffl;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getRepresentation(MemBuffer, Settings, int)
	 */
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		String val = "??";

		try {
			long b = getValue(buf);
			val = Long.toHexString(b).toUpperCase();
			val = StringFormat.padIt(val, 8, 'h', true);
		}
		catch (MemoryAccessException e) {
		}

		return val;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		try {
			return new Scalar(32, getValue(buf));
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

}
