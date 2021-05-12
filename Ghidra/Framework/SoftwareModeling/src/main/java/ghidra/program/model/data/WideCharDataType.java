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
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.StringUtilities;

public class WideCharDataType extends BuiltIn implements ArrayStringable, DataTypeWithCharset {
	final static SettingsDefinition[] DEFAULT_WIDE_CHAR_SETTINGS = new SettingsDefinition[] {
		EndianSettingsDefinition.DEF, RenderUnicodeSettingsDefinition.RENDER };

	/** A statically defined WideCharDataType instance.*/
	public final static WideCharDataType dataType = new WideCharDataType();

	public WideCharDataType() {
		this(null);
	}

	public WideCharDataType(DataTypeManager dtm) {
		super(null, "wchar_t", dtm);
	}

	@Override
	public int getLength() {
		return getDataOrganization().getWideCharSize();
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return true;
	}

	@Override
	public String getDescription() {
		return "Wide-Character (compiler-specific size)";
	}

	@Override
	protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return DEFAULT_WIDE_CHAR_SETTINGS;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new WideCharDataType(dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "wchar_t";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return new StringDataInstance(this, settings, buf, getLength()).getCharRepresentation();
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		length = getLength();
		try {
			switch (getLength()) {
				case 2:
					return Character.valueOf((char) buf.getShort(0));
				case 4:
					return new Scalar(32, buf.getInt(0), true);
			}
		}
		catch (MemoryAccessException e) {
			// ignore
		}
		return null;
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		switch (getLength()) {
			case 2:
				return Character.class;
			case 4:
				return Scalar.class;
			default:
				return null;
		}
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int length,
			DataTypeDisplayOptions options) {

		if (length != 2 && length != 4) {
			return "WCHAR_??";
		}

		StringBuilder strBuf = new StringBuilder();
		strBuf.append("WCHAR_");
		try {
			int val = (int) buf.getVarLengthUnsignedInt(0, length);
			if (StringUtilities.isAsciiChar(val)) {
				strBuf.append((char) val);
			}
			else {
				strBuf.append(Integer.toHexString(val));
				strBuf.append('h');
			}
		}
		catch (MemoryAccessException e) {
			strBuf.append("??");
		}
		return strBuf.toString();
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "WCHAR";
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(getName(), dataOrganization.getWideCharSize(), true,
			dataOrganization, false);
	}

	@Override
	public boolean hasStringValue(Settings settings) {
		return true;
	}

	@Override
	public String getArrayDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		return new StringDataInstance(this, settings, buf, len, true).getLabel(
			AbstractStringDataType.DEFAULT_UNICODE_ABBREV_PREFIX + "_",
			AbstractStringDataType.DEFAULT_UNICODE_LABEL_PREFIX,
			AbstractStringDataType.DEFAULT_UNICODE_LABEL, options);
	}

	@Override
	public String getArrayDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options, int offcutOffset) {
		return new StringDataInstance(this, settings, buf, len, true).getOffcutLabelString(
			AbstractStringDataType.DEFAULT_UNICODE_ABBREV_PREFIX + "_",
			AbstractStringDataType.DEFAULT_UNICODE_LABEL_PREFIX,
			AbstractStringDataType.DEFAULT_UNICODE_LABEL, options, offcutOffset);
	}

	@Override
	public String getCharsetName(Settings settings) {
		switch (getLength()) {
			case 2:
				return CharsetInfo.UTF16;
			case 4:
				return CharsetInfo.UTF32;
			default:
				return StringDataInstance.DEFAULT_CHARSET_NAME;
		}
	}
}
