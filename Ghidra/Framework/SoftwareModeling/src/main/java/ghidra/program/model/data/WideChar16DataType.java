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

import java.nio.CharBuffer;
import java.nio.charset.Charset;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.StringUtilities;

public class WideChar16DataType extends BuiltIn implements ArrayStringable, DataTypeWithCharset {

	/** A statically defined WideCharDataType instance. */
	public final static WideChar16DataType dataType = new WideChar16DataType();

	public WideChar16DataType() {
		this(null);
	}

	public WideChar16DataType(DataTypeManager dtm) {
		super(null, "wchar16", dtm);
	}

	@Override
	public int getLength() {
		return 2;
	}

	@Override
	public String getDescription() {
		return "Wide-Character (16-bit/UTF16)";
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new WideChar16DataType(dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "wchar16";
	}

	@Override
	protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return WideCharDataType.DEFAULT_WIDE_CHAR_SETTINGS;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return new StringDataInstance(this, settings, buf, getLength()).getCharRepresentation();
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		try {
			return Character.valueOf((char) buf.getUnsignedShort(0));
		}
		catch (MemoryAccessException e) {
			// ignore
		}
		return null;
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
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int length,
			DataTypeDisplayOptions options) {

		StringBuilder strBuf = new StringBuilder();
		strBuf.append("WCHAR16_");
		try {
			int val = buf.getUnsignedShort(0);
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
		return "WCHAR16";
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
		return CharsetInfo.UTF16;
	}
}
