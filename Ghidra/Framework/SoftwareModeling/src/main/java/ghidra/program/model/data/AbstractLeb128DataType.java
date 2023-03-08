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

import java.io.IOException;
import java.io.InputStream;

import ghidra.docking.settings.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.classfinder.ClassTranslator;

/**
 * An abstract base class for a LEB128 variable length integer data type.
 * <p>
 * See {@link LEB128}.
 */
public abstract class AbstractLeb128DataType extends BuiltIn implements Dynamic {

	/* package */ static final FormatSettingsDefinition FORMAT = FormatSettingsDefinition.DEF_HEX;

	private static SettingsDefinition[] SETTINGS_DEFS = { FORMAT };

	private final boolean signed;

	/**
	 * Base constructor for a little endian based 128 data type.
	 * @param name name of the leb128 data type that extends this class.
	 * @param signed true if it is signed. false if unsigned.
	 * @param dtm the data type manager to associate with this data type.
	 */
	public AbstractLeb128DataType(String name, boolean signed, DataTypeManager dtm) {
		super(null, name, dtm);
		this.signed = signed;
	}

	@Override
	protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return SETTINGS_DEFS;
	}


	@Override
	public int getLength() {
		return -1;
	}

	@Override
	public int getLength(MemBuffer buf, int maxLength) {
		if (maxLength < 0) {
			maxLength = LEB128.MAX_SUPPORTED_LENGTH;
		}
		try (InputStream is = buf.getInputStream(0, maxLength)) {
			return LEB128.getLength(is);
		}
		catch (IOException e) {
			return -1;
		}
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Scalar.class;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int maxLength) {
		if (maxLength < 0) {
			maxLength = LEB128.MAX_SUPPORTED_LENGTH;
		}

		try (InputStream is = buf.getInputStream(0, maxLength)) {
			long val = LEB128.read(is, signed);
			return new Scalar(64 - Long.numberOfLeadingZeros(val), val, signed);
		}
		catch (IOException e) {
			return null;	// memory error, or more than 10 bytes long
		}
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {

		Scalar val = (Scalar) getValue(buf, settings, length);
		if (val == null) {
			return "??";
		}

		int radix = FORMAT.getRadix(settings);
		String postfix = FORMAT.getRepresentationPostfix(settings);

		String valStr = val.toString(radix, false, signed, "", "");
		return valStr.toUpperCase() + postfix;
	}

	@Override
	public DataType getReplacementBaseType() {
		return ByteDataType.dataType;
	}

	@Override
	public boolean canSpecifyLength() {
		return true;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return name;
	}

}
