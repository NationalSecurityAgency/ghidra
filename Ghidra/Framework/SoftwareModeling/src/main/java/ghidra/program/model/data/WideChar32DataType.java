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

public class WideChar32DataType extends BuiltIn implements ArrayStringable, DataTypeWithCharset {

	/** A statically defined WideCharDataType instance. */
	public final static WideChar32DataType dataType = new WideChar32DataType();

	public WideChar32DataType() {
		this(null);
	}

	public WideChar32DataType(DataTypeManager dtm) {
		super(null, "wchar32", dtm);
	}

	@Override
	public int getLength() {
		return 4;
	}

	@Override
	public String getDescription() {
		return "Wide-Character (32-bit/UTF32)";
	}

	@Override
	protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return WideCharDataType.DEFAULT_WIDE_CHAR_SETTINGS;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new WideChar32DataType(dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "wchar32";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return new StringDataInstance(this, settings, buf, getLength()).getCharRepresentation();
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		try {
			// TODO: Not sure how we should encode this
			return new Scalar(32, buf.getInt(0), true);
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
		return Scalar.class;
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int length,
			DataTypeDisplayOptions options) {

		StringBuilder strBuf = new StringBuilder();
		strBuf.append("WCHAR32_");
		try {
			int val = buf.getInt(0);
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
		return "WCHAR32";
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
		return CharsetInfo.UTF32;
	}

}
