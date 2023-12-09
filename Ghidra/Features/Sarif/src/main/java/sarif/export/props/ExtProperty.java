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
package sarif.export.props;

import java.awt.Color;
import java.awt.Font;
import java.io.File;
import java.util.Date;

import javax.swing.KeyStroke;

import ghidra.framework.options.CustomOption;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.data.ISF.IsfObject;
import ghidra.util.exception.AssertException;

public class ExtProperty implements IsfObject {

	String name;
	String type;
	String value;

	public ExtProperty(String name, String type, String value) {
		this.name = name;
		this.type = type;
		this.value = value;
	}
	
	public ExtProperty(String name, Options propList) {
		this.name = name;
		OptionType optionType = propList.getType(name);
		switch (optionType) {
		case INT_TYPE:
			type = "int";
			value = Integer.toString(propList.getInt(name, 0));
			break;
		case LONG_TYPE:
			type = "long";
			value = Long.toString(propList.getLong(name, 0));
			break;
		case STRING_TYPE:
			type = "string";
			value = propList.getString(name, "");
			break;
		case BOOLEAN_TYPE:
			type = "bool";
			value = Boolean.toString(propList.getBoolean(name, true));
			break;
		case DOUBLE_TYPE:
			type = "double";
			value = Double.toString(propList.getDouble(name, 0));
			break;
		case FLOAT_TYPE:
			type = "float";
			value = Float.toString(propList.getFloat(name, 0f));
			break;
		case DATE_TYPE:
			type = "date";
			Date date = propList.getDate(name, (Date) null);
			long time = date == null ? 0 : date.getTime();
			value = Long.toHexString(time);
			break;
		case COLOR_TYPE:
			type = "color";
			Color color = propList.getColor(name, null);
			int rgb = color.getRGB();
			value = Integer.toHexString(rgb);
			break;
		case ENUM_TYPE:
			type = "enum";
			@SuppressWarnings({ "unchecked", "rawtypes" })
			Enum enuum = propList.getEnum(name, null);
			String enumString = OptionType.ENUM_TYPE.convertObjectToString(enuum);
			value = escapeElementEntities(enumString);
			break;
		case FILE_TYPE:
			type = "file";
			File file = propList.getFile(name, null);
			String path = file.getAbsolutePath();
			value = path;
			break;
		case FONT_TYPE:
			type = "font";
			Font font = propList.getFont(name, null);
			enumString = OptionType.FONT_TYPE.convertObjectToString(font);
			value = escapeElementEntities(enumString);
			break;
		case KEYSTROKE_TYPE:
			type = "keyStroke";
			KeyStroke keyStroke = propList.getKeyStroke(name, null);
			enumString = OptionType.KEYSTROKE_TYPE.convertObjectToString(keyStroke);
			value = escapeElementEntities(enumString);
			break;
		case CUSTOM_TYPE:
			type = "custom";
			CustomOption custom = propList.getCustomOption(name, null);
			enumString = OptionType.CUSTOM_TYPE.convertObjectToString(custom);
			value = escapeElementEntities(enumString);
			break;
		case BYTE_ARRAY_TYPE:
			type = "bytes";
			byte[] bytes = propList.getByteArray(name, null);
			enumString = OptionType.BYTE_ARRAY_TYPE.convertObjectToString(bytes);
			value = escapeElementEntities(enumString);
			break;
		case NO_TYPE:
			break;
		default:
			throw new AssertException();
		}
	}

	private static final String LESS_THAN = "&lt;";
	private static final String GREATER_THAN = "&gt;";
	private static final String APOSTROPHE = "&apos;";
	private static final String QUOTE = "&quot;";
	private static final String AMPERSAND = "&amp;";
	
	/**
	 * Converts any special or reserved characters in the specified SARIF string
	 * into the equivalent Unicode encoding.
	 * 
	 * @param sarif the SARIF string
	 * @return the encoded SARIF string
	 */
	public static String escapeElementEntities(String sarif) {
		StringBuilder buffer = new StringBuilder();
		for (int offset = 0; offset < sarif.length();) {
			int codePoint = sarif.codePointAt(offset);
			offset += Character.charCount(codePoint);

			if ((codePoint < ' ') && (codePoint != 0x09) && (codePoint != 0x0A) && (codePoint != 0x0D)) {
				continue;
			}
			if (codePoint >= 0x7F) {
				buffer.append("&#x");
				buffer.append(Integer.toString(codePoint, 16).toUpperCase());
				buffer.append(";");
				continue;
			}
			switch (codePoint) {
				case '<':
					buffer.append(LESS_THAN);
					break;
				case '>':
					buffer.append(GREATER_THAN);
					break;
				case '\'':
					buffer.append(APOSTROPHE);
					break;
				case '"':
					buffer.append(QUOTE);
					break;
				case '&':
					buffer.append(AMPERSAND);
					break;
				default:
					buffer.appendCodePoint(codePoint);
					break;
			}
		}
		return buffer.toString();
	}
}
