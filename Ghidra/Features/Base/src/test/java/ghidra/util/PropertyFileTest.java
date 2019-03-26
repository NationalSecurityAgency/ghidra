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
package ghidra.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.net.URLDecoder;
import java.net.URLEncoder;

import org.junit.Test;

import generic.test.AbstractGenericTest;

/**
 * 
 */
public class PropertyFileTest extends AbstractGenericTest {

	private static String NAME = "Test";

	/**
	 * Constructor for PropertyFileTest.
	 * @param arg0
	 */
	public PropertyFileTest() {
		super();
	}

	@Test
	public void testPropertyFile() throws Exception {

		String storageName = NamingUtilities.mangle(NAME);

		File parent = createTempDirectory(getName());

		PropertyFile pf = new PropertyFile(parent, storageName, "/", NAME);
		assertEquals(storageName, pf.getStorageName());
		assertEquals(NAME, pf.getName());
		assertEquals("/", pf.getParentPath());
		assertEquals("/" + NAME, pf.getPath());

		pf.putBoolean("TestBooleanTrue", true);
		pf.putBoolean("TestBooleanFalse", false);
		pf.putInt("TestInt", 1234);
		pf.putLong("TestLong", 0x12345678);

		StringBuffer sb = new StringBuffer("Line1\nLine2\n\"Ugly\" & Special <Values>; ");
		for (int i = 1; i < 35; i++) {
			sb.append((char) i);
		}
		for (int i = 0x70; i <= 0x80; i++) {
			sb.append((char) i);
		}
		String str = sb.toString();

		pf.putString("TestString", URLEncoder.encode(str, "UTF-8"));

		pf.writeState();

		PropertyFile pf2 = new PropertyFile(parent, storageName, "/", NAME);
		pf2.readState();

		assertTrue(pf2.getBoolean("TestBooleanTrue", false));
		assertTrue(!pf2.getBoolean("TestBooleanFalse", true));
		assertTrue(pf2.getBoolean("TestBooleanBad", true));
		assertEquals(1234, pf2.getInt("TestInt", -1));
		assertEquals(0x12345678, pf2.getLong("TestLong", -1));
		assertEquals(str, URLDecoder.decode(pf2.getString("TestString", null), "UTF-8"));

	}

}
