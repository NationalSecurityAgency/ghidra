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

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.NamingUtilities;
import ghidra.util.PropertyFile;

public class PropertyFileTest extends AbstractGenericTest {

	protected static String NAME = "Test";

	protected String storageName;
	protected File storageDir;

	public PropertyFileTest() {
		super();
	}

	@Before
	public void setUp() throws IOException {
		storageDir = createTempDirectory(getName());
		storageName = NamingUtilities.mangle(NAME);
	}

	protected PropertyFile getPropertyFile() throws IOException {
		return new PropertyFile(storageDir, storageName);
	}

	@Test
	public void testPropertyFile() throws Exception {

		PropertyFile pf = getPropertyFile();
		assertEquals(storageName, pf.getStorageName());

		pf.putBoolean("TestBooleanTrue", true);
		pf.putBoolean("TestBooleanFalse", false);
		pf.putInt("TestInt", 1234);
		pf.putLong("TestLong", 0x12345678);

		StringBuffer sb = new StringBuffer(
			"Line1\nLine2\n\"Ugly\" & Special <Values>; \u0128, \u0132, \307 and \253");
		for (int i = 1; i < 35; i++) {
			sb.append((char) i);
		}
		for (int i = 0x70; i <= 0x80; i++) {
			sb.append((char) i);
		}
		String str = sb.toString();

		pf.putString("TestString", URLEncoder.encode(str, "UTF-8"));

		// also test plain unicode values, as well as a 32bit unicode value
		String string2 = "non-control char values: < & ; > \u00bb \u0128, \u0132,  \uD835\uDCC8";
		pf.putString("TestString2", string2);

		pf.writeState();

		PropertyFile pf2 = getPropertyFile();
		assertTrue(pf2.exists()); // state will be read at construction time

		assertTrue(pf2.getBoolean("TestBooleanTrue", false));
		assertTrue(!pf2.getBoolean("TestBooleanFalse", true));
		assertTrue(pf2.getBoolean("TestBooleanBad", true));
		assertEquals(1234, pf2.getInt("TestInt", -1));
		assertEquals(0x12345678, pf2.getLong("TestLong", -1));
		assertEquals(str, URLDecoder.decode(pf2.getString("TestString", null), "UTF-8"));
		assertEquals(string2, pf2.getString("TestString2", null));

	}

}
