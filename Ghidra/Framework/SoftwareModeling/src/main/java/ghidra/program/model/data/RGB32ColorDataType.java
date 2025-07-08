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
import ghidra.program.model.data.RGB32EncodingSettingsDefinition.RGB32Encoding;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.DataConverter;

/**
 * {@link RGB32ColorDataType} provides a base implementation for 32-bit RGB Color values with 
 * an Alpha channel.  While this base implementation defaults to ARGB_8888 encoding a {@link TypeDef}
 * may be established with a different 32-bit encoding specified via a default setting of 
 * {@link RGB32EncodingSettingsDefinition}.
 */
public class RGB32ColorDataType extends AbstractColorDataType {

	public static RGB32ColorDataType datatype = new RGB32ColorDataType();

	private static int LENGTH = 4;

	private static TypeDefSettingsDefinition[] RGB32_TYPEDEF_SETTINGS = TypeDefSettingsDefinition
			.concat(UnsignedIntegerDataType.dataType.getTypeDefSettingsDefinitions(),
				RGB32EncodingSettingsDefinition.DEF);

	/**
	 * Generate a 32-bit RGB typedef with a specific encoding
	 * @param rgb32Encoding 32-bit RGB encoding
	 * @return RGB32 typedef
	 */
	public static TypedefDataType createRGB32Typedef(RGB32Encoding rgb32Encoding) {
		Objects.requireNonNull(rgb32Encoding, "RGB32Encoding required");
		TypedefDataType dt = new TypedefDataType(rgb32Encoding.name(), datatype);
		Settings settings = dt.getDefaultSettings();
		RGB32EncodingSettingsDefinition.DEF.setRGBEncoding(settings, rgb32Encoding);
		return dt;
	}

	public RGB32ColorDataType() {
		this(null);
	}

	public RGB32ColorDataType(DataTypeManager dtm) {
		super("RGB32", dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new RGB32ColorDataType(dtm);
	}

	@Override
	public int getLength() {
		return LENGTH;
	}

	@Override
	public String getDescription() {
		return "An RGB color with 32-bit encoding (default encoding is ARGB_8888, use Typedef for other 32-bit encodings)";
	}

	@Override
	public TypeDefSettingsDefinition[] getTypeDefSettingsDefinitions() {
		return RGB32_TYPEDEF_SETTINGS;
	}

	@Override
	protected Color decodeColor(MemBuffer buf, Settings settings) {

		byte[] bytes = new byte[LENGTH];
		buf.getBytes(bytes, 0);

		int value = DataConverter.getInstance(ENDIAN.isBigEndian(settings, buf)).getInt(bytes, 0);

		// Convert encoding to 32-bit ARGB_8888 value used by Java Color instantiation
		RGB32Encoding rgbEncoding = RGB32EncodingSettingsDefinition.DEF.getRGBEncoding(settings);
		switch (rgbEncoding) {
			case ARGB_8888:
				break;
			case RGBA_8888: {
				int alpha = value & 0xff;
				int rgb = value >>> 8;
				value = rgb + (alpha << 24);
				break;
			}
			case BGRA_8888: {
				value = Integer.reverseBytes(value);
				break;
			}
			case ABGR_8888: {
				int rgb = Integer.reverseBytes(value) >>> 8;
				value = rgb + (value & 0xff000000);
				break;
			}
			default:
				throw new AssertionError("Missing RGB32 Encoding support: " + rgbEncoding);
		}

		// 32-bit ARGB_8888 Encoding is used by Java Color
		return new Color(value, true);
	}

	@Override
	protected String getEncodingName(Settings settings) {
		return RGB32EncodingSettingsDefinition.DEF.getRGBEncoding(settings).name();
	}

	@Override
	protected List<ComponentValue> getComponentValues(MemBuffer buf, Settings settings) {

		byte[] bytes = new byte[LENGTH];
		buf.getBytes(bytes, 0);

		int value = DataConverter.getInstance(ENDIAN.isBigEndian(settings, buf)).getInt(bytes, 0);

		List<ComponentValue> list = new ArrayList<>();

		RGB32Encoding rgbEncoding = RGB32EncodingSettingsDefinition.DEF.getRGBEncoding(settings);
		switch (rgbEncoding) {
			case ARGB_8888:
				list.add(new ComponentValue("A", getFieldValue(value, 24, 0xff), 8));
				list.add(new ComponentValue("R", getFieldValue(value, 16, 0xff), 8));
				list.add(new ComponentValue("G", getFieldValue(value, 8, 0xff), 8));
				list.add(new ComponentValue("B", getFieldValue(value, 0, 0xff), 8));
				break;
			case RGBA_8888: {
				list.add(new ComponentValue("R", getFieldValue(value, 24, 0xff), 8));
				list.add(new ComponentValue("G", getFieldValue(value, 16, 0xff), 8));
				list.add(new ComponentValue("B", getFieldValue(value, 8, 0xff), 8));
				list.add(new ComponentValue("A", getFieldValue(value, 0, 0xff), 8));
				break;
			}
			case BGRA_8888: {
				list.add(new ComponentValue("B", getFieldValue(value, 24, 0xff), 8));
				list.add(new ComponentValue("G", getFieldValue(value, 16, 0xff), 8));
				list.add(new ComponentValue("R", getFieldValue(value, 8, 0xff), 8));
				list.add(new ComponentValue("A", getFieldValue(value, 0, 0xff), 8));
				break;
			}
			case ABGR_8888: {
				list.add(new ComponentValue("A", getFieldValue(value, 24, 0xff), 8));
				list.add(new ComponentValue("B", getFieldValue(value, 16, 0xff), 8));
				list.add(new ComponentValue("G", getFieldValue(value, 8, 0xff), 8));
				list.add(new ComponentValue("R", getFieldValue(value, 0, 0xff), 8));
				break;
			}
			default:
				throw new AssertionError("Missing RGB32 Encoding support: " + rgbEncoding);
		}
		return list;
	}

}
