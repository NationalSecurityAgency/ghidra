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
 * Provides an implementation of a byte that has not been defined yet as a
 * particular type of data in the program.
 */
public class Undefined7DataType extends Undefined {
	static {
		ClassTranslator.put("ghidra.program.model.data.Undefined7",
			Undefined7DataType.class.getName());
	}

	private final static long serialVersionUID = 1;

	/** A statically defined DefaultDataType used when an Undefined byte is needed.*/
	public final static Undefined7DataType dataType = new Undefined7DataType();

	/**
	 * Constructs a new Undefined1 dataType
	 *
	 */
	public Undefined7DataType() {
		this(null);
	}

	public Undefined7DataType(DataTypeManager dtm) {
		super("undefined7", dtm);
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	@Override
	public int getLength() {
		return 7;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	@Override
	public String getDescription() {
		return "Undefined 7-Byte";
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getMnemonic(Settings)
	 */
	@Override
	public String getMnemonic(Settings settings) {
		return name;
	}

	private long getValue(MemBuffer buf) throws MemoryAccessException {
		long val =
			(buf.getInt(0) << 24) + ((buf.getShort(4) & 0xffffl) << 8) + (buf.getByte(6) & 0xffl);
		return val & 0xffffffffffffl;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getRepresentation(MemBuffer, Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		String val = "??";

		try {
			long b = getValue(buf);
			val = Long.toHexString(b).toUpperCase();
			val = StringFormat.padIt(val, 14, 'h', true);
		}
		catch (MemoryAccessException e) {
		}

		return val;
	}

	/**
	 * 
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		try {
			return new Scalar(56, getValue(buf));
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Undefined7DataType(dtm);
	}
}
