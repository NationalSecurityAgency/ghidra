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
package ghidra.framework.options;

import java.awt.Color;
import java.awt.Font;
import java.io.*;
import java.util.Date;

import javax.swing.KeyStroke;

import org.jdom.*;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;

import ghidra.util.Msg;
import ghidra.util.xml.GenericXMLOutputter;
import ghidra.util.xml.XmlUtilities;

public enum OptionType {
	INT_TYPE(Integer.class, new IntStringAdapter()),
	LONG_TYPE(Long.class, new LongStringAdapter()),
	STRING_TYPE(String.class, new StringStringAdapter()),
	DOUBLE_TYPE(Double.class, new DoubleStringAdapter()),
	BOOLEAN_TYPE(Boolean.class, new BooleanStringAdapter()),
	DATE_TYPE(Date.class, new DateStringAdapter()),
	NO_TYPE(null, new NoTypeStringAdapter()),
	FLOAT_TYPE(Float.class, new FloatStringAdapter()),
	ENUM_TYPE(Enum.class, new EnumStringAdapter()),
	CUSTOM_TYPE(CustomOption.class, new CustomStringAdapter()),
	BYTE_ARRAY_TYPE(byte[].class, new ByteArrayStringAdapter()),
	FILE_TYPE(File.class, new FileStringAdapter()),
	COLOR_TYPE(Color.class, new ColorStringAdapter()),
	FONT_TYPE(Font.class, new FontStringAdapter()),
	KEYSTROKE_TYPE(KeyStroke.class, new KeyStrokeStringAdapter());

	private Class<?> clazz;
	private StringAdapter stringAdapter;

	public Object convertStringToObject(String string) {
		if (string == null) {
			return null;
		}
		return stringAdapter.stringToObject(string);
	}

	public String convertObjectToString(Object object) {
		if (object == null) {
			return null;
		}
		return stringAdapter.objectToString(object);
	}

	public Class<?> getValueClass() {
		return clazz;
	}

	OptionType(Class<?> clazz, StringAdapter adapter) {
		this.clazz = clazz;
		this.stringAdapter = adapter;
	}

	public static OptionType getOptionType(Object obj) {
		if (obj == null) {
			return NO_TYPE;
		}
		Class<? extends Object> objClass = obj.getClass();
		for (OptionType type : values()) {
			if (type == NO_TYPE) {
				continue;
			}
			if (type.clazz.isAssignableFrom(objClass)) {
				return type;
			}
		}
		return OptionType.NO_TYPE;
	}

	static abstract class StringAdapter {
		abstract Object stringToObject(String string);

		String objectToString(Object object) {
			return object.toString();
		}
	}

	static class IntStringAdapter extends StringAdapter {
		@Override
		Object stringToObject(String string) {
			return Integer.valueOf(string);
		}
	}

	static class LongStringAdapter extends StringAdapter {
		@Override
		Object stringToObject(String string) {
			return Long.valueOf(string);
		}
	}

	static class StringStringAdapter extends StringAdapter {
		@Override
		Object stringToObject(String string) {
			return string;
		}
	}

	static class DoubleStringAdapter extends StringAdapter {
		@Override
		Object stringToObject(String string) {
			return Double.valueOf(string);
		}
	}

	static class BooleanStringAdapter extends StringAdapter {
		@Override
		Object stringToObject(String string) {
			return Boolean.valueOf(string);
		}
	}

	static class DateStringAdapter extends StringAdapter {
		@Override
		Object stringToObject(String string) {
			return new Date(Long.parseLong(string));
		}

		@Override
		String objectToString(Object object) {
			Date date = (Date) object;
			return Long.toString(date.getTime());
		}
	}

	static class NoTypeStringAdapter extends StringAdapter {
		@Override
		Object stringToObject(String string) {
			return null;
		}
	}

	static class FloatStringAdapter extends StringAdapter {
		@Override
		Object stringToObject(String string) {
			return Float.valueOf(string);
		}
	}

	static class EnumStringAdapter extends StringAdapter {
		@Override
		Object stringToObject(String string) {
			SaveState saveState = getSaveStateFromXmlString(string);

			// compiler problem on test machine requires this dummy so it knows the type
			DUMMY nullDummy = null;
			return saveState.getEnum("ENUM", nullDummy);
		}

		@Override
		String objectToString(Object object) {
			Enum<?> enuum = (Enum<?>) object;
			SaveState saveState = new SaveState();
			saveState.putEnum("ENUM", enuum);
			return saveToXmlString(saveState);

		}
	}

	private static String saveToXmlString(SaveState saveState) {
		Element element = saveState.saveToXml();
		StringWriter stringWriter = new StringWriter();
		XMLOutputter xmlout = new GenericXMLOutputter();
		try {
			xmlout.output(element, stringWriter);
		}
		catch (IOException e) {
			// can't happen as long as we are using a  StringWriter
		}
		return stringWriter.toString();
	}

	private static SaveState getSaveStateFromXmlString(String xmlString) {
		SAXBuilder saxBuilder = XmlUtilities.createSecureSAXBuilder(false, false);
		try {
			Document doc = saxBuilder.build(new StringReader(xmlString));
			Element rootElement = doc.getRootElement();
			return new SaveState(rootElement);
		}
		catch (JDOMException e) {
			Msg.showError(SaveState.class, null, "XML Error", "Error in xml in saved property", e);
		}
		catch (IOException e) {
			// can't happen as long as we are using a  StringReader
		}
		return new SaveState();
	}

	static enum DUMMY {
		// nothing; just a dummy
	}

	static class CustomStringAdapter extends StringAdapter {
		@Override
		Object stringToObject(String string) {
			SaveState saveState = getSaveStateFromXmlString(string);
			String customOptionClassName =
				saveState.getString(CustomOption.CUSTOM_OPTION_CLASS_NAME_KEY, null);
			try {
				Class<?> c = Class.forName(customOptionClassName);
				CustomOption option = (CustomOption) c.getConstructor().newInstance();
				option.readState(saveState);
				return option;
			}
			catch (ClassNotFoundException e) {
				Msg.warn(this,
					"Ignoring unsupported customOption instance for: " + customOptionClassName);
			}
			catch (Exception e) {
				Msg.error(this,
					"Can't create customOption instance for: " + customOptionClassName + 
					e);
			}
			return null;
		}

		@Override
		String objectToString(Object object) {
			CustomOption customOption = (CustomOption) object;
			SaveState saveState = new SaveState();
			saveState.putString(CustomOption.CUSTOM_OPTION_CLASS_NAME_KEY,
				object.getClass().getName());
			customOption.writeState(saveState);
			return saveToXmlString(saveState);
		}
	}

	public static class ByteArrayStringAdapter extends StringAdapter {
		@Override
		Object stringToObject(String string) {
			SaveState saveState = getSaveStateFromXmlString(string);
			return saveState.getBytes("BYTES", null);
		}

		@Override
		String objectToString(Object object) {
			byte[] bytes = (byte[]) object;
			SaveState saveState = new SaveState();
			saveState.putBytes("BYTES", bytes);
			return saveToXmlString(saveState);
		}

	}

	static class FileStringAdapter extends StringAdapter {
		@Override
		Object stringToObject(String string) {
			return new File(string);
		}

		@Override
		String objectToString(Object object) {
			return ((File) object).getAbsolutePath();
		}
	}

	static class ColorStringAdapter extends StringAdapter {
		@Override
		Object stringToObject(String string) {
			return new Color(Integer.decode(string));
		}

		@Override
		String objectToString(Object object) {
			return Integer.toString(((Color) object).getRGB());
		}
	}

	static class FontStringAdapter extends StringAdapter {
		private static final String[] STYLES =
			new String[] { "PLAIN", "BOLD", "ITALIC", "BOLDITALIC" };

		@Override
		Object stringToObject(String string) {
			return Font.decode(string);
		}

		@Override
		String objectToString(Object object) {
			Font font = (Font) object;
			String fontName = font.getFamily();
			int style = font.getStyle();
			int size = font.getSize();
			StringBuffer buf = new StringBuffer();
			buf.append(fontName);
			buf.append("-");
			buf.append(STYLES[style]);
			buf.append("-");
			buf.append(size);
			return buf.toString();
		}
	}

	static class KeyStrokeStringAdapter extends StringAdapter {
		@Override
		Object stringToObject(String string) {
			return KeyStroke.getKeyStroke(string);
		}

	}
}
