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

import ghidra.docking.settings.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.StringFormat;
import ghidra.util.classfinder.ClassTranslator;

/**
 * Provides a definition of an primitive char in a program. The size and signed-ness of this type is
 * determined by the data organization of the associated data type manager.
 */
public class CharDataType extends AbstractIntegerDataType implements DataTypeWithCharset {
	private final static long serialVersionUID = 1;

	static {
		ClassTranslator.put("ghidra.program.model.data.AsciiDataType",
			CharDataType.class.getName());
	}

	private static SettingsDefinition[] CHAR_SETTINGS_DEFS =
		{ FormatSettingsDefinition.DEF_CHAR, PADDING, ENDIAN, MNEMONIC,
			CharsetSettingsDefinition.CHARSET, RenderUnicodeSettingsDefinition.RENDER };

	private static SettingsDefinition[] WIDE_UTF_CHAR_SETTINGS_DEFS =
		{ FormatSettingsDefinition.DEF_CHAR, PADDING, ENDIAN, MNEMONIC,
			RenderUnicodeSettingsDefinition.RENDER };

	public static final CharDataType dataType = new CharDataType();

	/**
	 * Constructs a new char datatype.
	 */
	public CharDataType() {
		this(null);
	}

	public CharDataType(DataTypeManager dtm) {
		this("char", dtm);
	}

	protected CharDataType(String name, boolean signed, DataTypeManager dtm) {
		super(name, signed, dtm);
	}

	private CharDataType(String name, DataTypeManager dtm) {
		super(name, isSignedChar(dtm), dtm);
	}

	@Override
	protected FormatSettingsDefinition getFormatSettingsDefinition() {
		return FormatSettingsDefinition.DEF_CHAR;
	}

	@Override
	protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return isWideUTFChar() ? WIDE_UTF_CHAR_SETTINGS_DEFS : CHAR_SETTINGS_DEFS;
	}

	private boolean isWideUTFChar() {
		return getLength() != 1;
	}

	private static boolean isSignedChar(DataTypeManager dtm) {
		DataOrganization dataOrganization =
			dtm != null ? dtm.getDataOrganization() : DataOrganizationImpl.getDefaultOrganization();
		return dataOrganization.isSignedChar();
	}

	/**
	 * Returns the C style data-type declaration for this data-type. Null is returned if no
	 * appropriate declaration exists.
	 */
	@Override
	public String getCDeclaration() {
		return name;
	}

	@Override
	public int getLength() {
		return getDataOrganization().getCharSize();
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return true;
	}

	@Override
	public String getDescription() {
		return "Character";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		try {
			int size = getLength();
			if (size == 1) {
				return Character.valueOf((char) buf.getUnsignedByte(0));
			}
			int val = -1;
			if (size == 2) {
				val = buf.getShort(0);
			}
			if (size == 4) {
				val = buf.getInt(0);
			}
			if (val >= 0 && val <= Character.MAX_VALUE) {
				return Character.valueOf((char) val);
			}
			return null;
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	@Override
	public boolean isEncodable() {
		return true;
	}

	@Override
	public byte[] encodeValue(Object value, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException {
		return encodeCharacterValue(value, buf, settings);
	}

	@Override
	public byte[] encodeRepresentation(String repr, MemBuffer buf, Settings settings, int length)
			throws DataTypeEncodeException {
		return encodeCharacterRepresentation(repr, buf, settings);
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Character.class;
	}

	@Override
	public CharDataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new CharDataType(dtm);
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int length,
			DataTypeDisplayOptions options) {

		StringBuilder strBuf = new StringBuilder(getDefaultLabelPrefix());
		strBuf.append("_");
		try {
			byte b = buf.getByte(0);
			if (b > 31 && b < 128) {
				strBuf.append((char) b);
			}
			else {
				strBuf.append(StringFormat.hexByteString(b));
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
		return "CHAR";
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return null;		// Standard C primitive
	}

	@Override
	public CharDataType getOppositeSignednessDataType() {
		return isSigned() ? UnsignedCharDataType.dataType.clone(getDataTypeManager())
				: SignedCharDataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public String getCharsetName(Settings settings) {
		switch (getLength()) {
			case 1:
				return CharsetSettingsDefinition.CHARSET.getCharset(settings,
					StringDataInstance.DEFAULT_CHARSET_NAME);
			case 2:
				return CharsetInfo.UTF16;
			case 4:
				return CharsetInfo.UTF32;
			default:
				return StringDataInstance.DEFAULT_CHARSET_NAME;
		}
	}

}
