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

import java.awt.Color;
import java.util.*;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.RGB16EncodingSettingsDefinition.RGB16Encoding;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.DataConverter;

/**
 * {@link RGB16ColorDataType} provides a base implementation for 16-bit RGB Color values.  
 * While this base implementation defaults to RGB_565 encoding a {@link TypeDef}
 * may be established with a different 16-bit encoding specified via a default setting of 
 * {@link RGB16EncodingSettingsDefinition}.
 */
public class RGB16ColorDataType extends AbstractColorDataType {

	public static RGB16ColorDataType datatype = new RGB16ColorDataType();

	private static int LENGTH = 2;

	private static TypeDefSettingsDefinition[] RGB16_TYPEDEF_SETTINGS = TypeDefSettingsDefinition
			.concat(UnsignedIntegerDataType.dataType.getTypeDefSettingsDefinitions(),
				RGB16EncodingSettingsDefinition.DEF);

	/**
	 * Generate a 16-bit RGB typedef with a specific encoding
	 * @param rgb16Encoding 16-bit RGB encoding
	 * @return RGB16 typedef
	 */
	public static TypedefDataType createRGB16Typedef(RGB16Encoding rgb16Encoding) {
		Objects.requireNonNull(rgb16Encoding, "RGB16Encoding required");
		TypedefDataType dt = new TypedefDataType(rgb16Encoding.name(), datatype);
		Settings settings = dt.getDefaultSettings();
		RGB16EncodingSettingsDefinition.DEF.setRGBEncoding(settings, rgb16Encoding);
		return dt;
	}

	public RGB16ColorDataType() {
		this(null);
	}

	public RGB16ColorDataType(DataTypeManager dtm) {
		super("RGB16", dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new RGB16ColorDataType(dtm);
	}

	@Override
	public int getLength() {
		return LENGTH;
	}

	@Override
	public String getDescription() {
		return "An RGB color with 16-bit encoding (default encoding is RGB_565, use Typedef for other 16-bit encodings)";
	}

	@Override
	public TypeDefSettingsDefinition[] getTypeDefSettingsDefinitions() {
		return RGB16_TYPEDEF_SETTINGS;
	}

	@Override
	protected Color decodeColor(MemBuffer buf, Settings settings) {

		byte[] bytes = new byte[LENGTH];
		buf.getBytes(bytes, 0);

		int value = DataConverter.getInstance(ENDIAN.isBigEndian(settings, buf)).getShort(bytes, 0);
		int argbValue = 0; // scaled ARGB_8888 value

		// Convert encoding to default ARGB_8888 value used by Java Color instantiation
		RGB16Encoding rgbEncoding = RGB16EncodingSettingsDefinition.DEF.getRGBEncoding(settings);
		switch (rgbEncoding) {
			case RGB_565:
				argbValue = 0xff << 24; // Alpha (enabled)
				argbValue |= scaleFieldValue(getFieldValue(value, 11, 0x1f), 5) << 16; // R
				argbValue |= scaleFieldValue(getFieldValue(value, 6, 0x3f), 6) << 8; // G
				argbValue |= scaleFieldValue(getFieldValue(value, 0, 0x1f), 5); // B
				break;
			case RGB_555: {
				argbValue = 0xff << 24; // Alpha (enabled)
				argbValue |= scaleFieldValue(getFieldValue(value, 10, 0x1f), 5) << 16; // R
				argbValue |= scaleFieldValue(getFieldValue(value, 5, 0x1f), 5) << 8; // G
				argbValue |= scaleFieldValue(getFieldValue(value, 0, 0x1f), 5); // B
				break;
			}
			case ARGB_1555: {
				argbValue = (0xff * getFieldValue(value, 15, 0x1)) << 24; // Alpha
				argbValue |= scaleFieldValue(getFieldValue(value, 10, 0x1f), 5) << 16; // R
				argbValue |= scaleFieldValue(getFieldValue(value, 5, 0x1f), 5) << 8; // G
				argbValue |= scaleFieldValue(getFieldValue(value, 0, 0x1f), 5); // B
				break;
			}
			default:
				throw new AssertionError("Missing RGB16 Encoding support: " + rgbEncoding);
		}

		// 32-bit ARGB_8888 Encoding is used by Java Color
		return new Color(argbValue, true);
	}

	@Override
	protected String getEncodingName(Settings settings) {
		return RGB16EncodingSettingsDefinition.DEF.getRGBEncoding(settings).name();
	}

	@Override
	protected List<ComponentValue> getComponentValues(MemBuffer buf, Settings settings) {

		byte[] bytes = new byte[LENGTH];
		buf.getBytes(bytes, 0);

		int value = DataConverter.getInstance(ENDIAN.isBigEndian(settings, buf)).getShort(bytes, 0);

		List<ComponentValue> list = new ArrayList<>();

		RGB16Encoding rgbEncoding = RGB16EncodingSettingsDefinition.DEF.getRGBEncoding(settings);
		switch (rgbEncoding) {
			case RGB_565:
				list.add(new ComponentValue("R", getFieldValue(value, 11, 0x1f), 5));
				list.add(new ComponentValue("G", getFieldValue(value, 6, 0x3f), 6));
				list.add(new ComponentValue("B", getFieldValue(value, 0, 0x1f), 5));
				break;
			case RGB_555: {
				list.add(new ComponentValue("R", getFieldValue(value, 10, 0x1f), 5));
				list.add(new ComponentValue("G", getFieldValue(value, 5, 0x1f), 5));
				list.add(new ComponentValue("B", getFieldValue(value, 0, 0x1f), 5));
				break;
			}
			case ARGB_1555: {
				list.add(new ComponentValue("A", getFieldValue(value, 15, 0x1), 1));
				list.add(new ComponentValue("R", getFieldValue(value, 10, 0x1f), 5));
				list.add(new ComponentValue("G", getFieldValue(value, 5, 0x1f), 5));
				list.add(new ComponentValue("B", getFieldValue(value, 0, 0x1f), 5));
				break;
			}
			default:
				throw new AssertionError("Missing RGB16 Encoding support: " + rgbEncoding);
		}
		return list;
	}

}
