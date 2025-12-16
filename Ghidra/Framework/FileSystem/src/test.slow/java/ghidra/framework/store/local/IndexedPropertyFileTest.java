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
package ghidra.framework.store.local;

import static org.junit.Assert.*;

import java.io.File;
import java.net.URLDecoder;
import java.net.URLEncoder;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.NamingUtilities;
import ghidra.util.PropertyFile;

public class IndexedPropertyFileTest extends AbstractGenericTest {

	private static String NAME = "IndexTest";

	@Test
	public void testPropertyFile() throws Exception {

		File parent = createTempDirectory(getName());

		String storageName = NamingUtilities.mangle(NAME);

		ItemPropertyFile pf = new IndexedPropertyFile(parent, storageName, "/", NAME);
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

		pf = new IndexedPropertyFile(parent, storageName, "/X", "XXX");
		// existing file ignores supplied name and parent path
		assertEquals(storageName, pf.getStorageName());
		assertEquals(NAME, pf.getName());
		assertEquals("/", pf.getParentPath());
		assertEquals("/" + NAME, pf.getPath());
		assertTrue(pf.getBoolean("TestBooleanTrue", false));
		assertTrue(!pf.getBoolean("TestBooleanFalse", true));
		assertTrue(pf.getBoolean("TestBooleanBad", true));
		assertEquals(1234, pf.getInt("TestInt", -1));
		assertEquals(0x12345678, pf.getLong("TestLong", -1));
		assertEquals(str, URLDecoder.decode(pf.getString("TestString", null), "UTF-8"));

		pf = new IndexedPropertyFile(parent, storageName);
		assertEquals(storageName, pf.getStorageName());
		assertEquals(NAME, pf.getName());
		assertEquals("/", pf.getParentPath());
		assertEquals("/" + NAME, pf.getPath());

		assertTrue(pf.getBoolean("TestBooleanTrue", false));
		assertTrue(!pf.getBoolean("TestBooleanFalse", true));
		assertTrue(pf.getBoolean("TestBooleanBad", true));
		assertEquals(1234, pf.getInt("TestInt", -1));
		assertEquals(0x12345678, pf.getLong("TestLong", -1));
		assertEquals(str, URLDecoder.decode(pf.getString("TestString", null), "UTF-8"));

		pf = new IndexedPropertyFile(new File(parent, storageName + PropertyFile.PROPERTY_EXT));
		assertEquals(storageName, pf.getStorageName());
		assertEquals(NAME, pf.getName());
		assertEquals("/", pf.getParentPath());
		assertEquals("/" + NAME, pf.getPath());

		assertTrue(pf.getBoolean("TestBooleanTrue", false));
		assertTrue(!pf.getBoolean("TestBooleanFalse", true));
		assertTrue(pf.getBoolean("TestBooleanBad", true));
		assertEquals(1234, pf.getInt("TestInt", -1));
		assertEquals(0x12345678, pf.getLong("TestLong", -1));
		assertEquals(str, URLDecoder.decode(pf.getString("TestString", null), "UTF-8"));

	}

}
