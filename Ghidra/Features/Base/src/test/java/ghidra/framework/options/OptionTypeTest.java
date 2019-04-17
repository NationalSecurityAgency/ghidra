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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.awt.Color;
import java.awt.Font;
import java.io.File;
import java.util.Date;

import javax.swing.KeyStroke;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class OptionTypeTest extends AbstractGenericTest {
	static public enum FOO {
		AAA, BBB, CCC
	}

	public OptionTypeTest() {
		super();
	}

	@Test
    public void testIntConversion() {
		String string = OptionType.INT_TYPE.convertObjectToString(7);
		assertEquals(Integer.valueOf(7), OptionType.INT_TYPE.convertStringToObject(string));
	}

	@Test
    public void testLongConversion() {
		String string = OptionType.LONG_TYPE.convertObjectToString(7);
		assertEquals(Long.valueOf(7), OptionType.LONG_TYPE.convertStringToObject(string));
	}

	@Test
    public void testFloatConversion() {
		String string = OptionType.FLOAT_TYPE.convertObjectToString(2.5);
		assertEquals(Float.valueOf(2.5f), OptionType.FLOAT_TYPE.convertStringToObject(string));
	}

	@Test
    public void testDoubleConversion() {
		String string = OptionType.DOUBLE_TYPE.convertObjectToString(2.5);
		assertEquals(Double.valueOf(2.5f), OptionType.DOUBLE_TYPE.convertStringToObject(string));
	}

	@Test
    public void testStringConversion() {
		String string = OptionType.STRING_TYPE.convertObjectToString("HEY");
		assertEquals("HEY", OptionType.STRING_TYPE.convertStringToObject(string));
	}

	@Test
    public void testBooleanConversion() {
		String string = OptionType.BOOLEAN_TYPE.convertObjectToString(Boolean.FALSE);
		assertEquals(Boolean.FALSE, OptionType.BOOLEAN_TYPE.convertStringToObject(string));
	}

	@Test
    public void testDateConversion() {
		Date date = new Date();
		String string = OptionType.DATE_TYPE.convertObjectToString(date);
		assertEquals(date, OptionType.DATE_TYPE.convertStringToObject(string));
	}

	@Test
    public void testEnumConversion() {
		String string = OptionType.ENUM_TYPE.convertObjectToString(FOO.BBB);
		assertEquals(FOO.BBB, OptionType.ENUM_TYPE.convertStringToObject(string));
	}

	@Test
    public void testCustomConversion() {
		String string = OptionType.CUSTOM_TYPE.convertObjectToString(new MyCustomOption(5, "ABC"));
		assertEquals(new MyCustomOption(5, "ABC"),
			OptionType.CUSTOM_TYPE.convertStringToObject(string));
	}

	@Test
    public void testByteArrayConversion() {
		byte[] bytes = { (byte) 3, (byte) 4 };
		String string = OptionType.BYTE_ARRAY_TYPE.convertObjectToString(bytes);
		byte[] newBytes = (byte[]) OptionType.BYTE_ARRAY_TYPE.convertStringToObject(string);
		assertEquals(2, newBytes.length);
		assertEquals(3, newBytes[0]);
		assertEquals(4, newBytes[1]);
	}

	@Test
    public void testFileConversion() {
		String testPath = "users/bin/what";
		File file = new File(testPath);
		String string = OptionType.FILE_TYPE.convertObjectToString(file);
		File reloadedFile = (File) OptionType.FILE_TYPE.convertStringToObject(string);
		String absolutePath = reloadedFile.getAbsolutePath();
		absolutePath = absolutePath.replaceAll("\\\\", "/");
		assertTrue(absolutePath.contains(testPath));
	}

	@Test
    public void testColorConversion() {
		Color c = new Color(100, 150, 200);
		String string = OptionType.COLOR_TYPE.convertObjectToString(c);
		assertEquals(c, OptionType.COLOR_TYPE.convertStringToObject(string));
	}

	@Test
    public void testFontConversion() {
		Font font = new Font("Monospaced", Font.BOLD, 24);
		String string = OptionType.FONT_TYPE.convertObjectToString(font);
		assertEquals(font, OptionType.FONT_TYPE.convertStringToObject(string));
	}

	@Test
    public void testKeyStrokeConversion() {
		KeyStroke keyStroke = KeyStroke.getKeyStroke('+');
		String string = OptionType.KEYSTROKE_TYPE.convertObjectToString(keyStroke);
		assertEquals(keyStroke, OptionType.KEYSTROKE_TYPE.convertStringToObject(string));
	}

	public static class MyCustomOption implements CustomOption {
		int a;
		String b;

		public MyCustomOption() {
			// needed for restoring from xml
		}

		public MyCustomOption(int a, String b) {
			this.a = a;
			this.b = b;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + a;
			result = prime * result + ((b == null) ? 0 : b.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			MyCustomOption other = (MyCustomOption) obj;
			if (a != other.a)
				return false;
			if (b == null) {
				if (other.b != null)
					return false;
			}
			else if (!b.equals(other.b))
				return false;
			return true;
		}

		@Override
		public void readState(SaveState saveState) {
			a = saveState.getInt("a", 0);
			b = saveState.getString("b", null);
		}

		@Override
		public void writeState(SaveState saveState) {
			saveState.putInt("a", a);
			saveState.putString("b", b);
		}

	}
}
