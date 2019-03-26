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
package ghidra.formats.gfilesystem;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public class FSUtilitiesTest {

	@Test
	public void testAppendPath() {

		assertNull(FSUtilities.appendPath());
		assertNull(FSUtilities.appendPath(null, null));
		assertNull(FSUtilities.appendPath(null, null, null));

		assertEquals("", FSUtilities.appendPath("", ""));
		assertEquals("", FSUtilities.appendPath(""));
		assertEquals("", FSUtilities.appendPath("", "", ""));

		assertEquals("    ", FSUtilities.appendPath("    "));
		assertEquals("    /\t", FSUtilities.appendPath("    ", "\t"));

		assertEquals("/", FSUtilities.appendPath("/", ""));
		assertEquals("/", FSUtilities.appendPath("/", null));
		assertEquals("/", FSUtilities.appendPath("/", null, ""));
		assertEquals("/", FSUtilities.appendPath("/", null, null));

		assertEquals("/", FSUtilities.appendPath("", null, "/"));

		assertEquals("blah", FSUtilities.appendPath("", "blah"));
		assertEquals("/blah", FSUtilities.appendPath("", null, "/blah"));
		assertEquals("blah", FSUtilities.appendPath("", null, "blah"));

		assertEquals("/blah/leading", FSUtilities.appendPath("/blah/", "/leading"));

		assertEquals("/blah/leading/dir", FSUtilities.appendPath("/blah/", "/leading", "dir"));

		assertEquals("blah", FSUtilities.appendPath("blah"));
		assertEquals("blah/sub", FSUtilities.appendPath("blah", "sub"));
		assertEquals("blah/sub", FSUtilities.appendPath("blah/", "sub"));

		assertEquals("blah\\sub", FSUtilities.appendPath("blah\\", "sub"));
		assertEquals("blah/sub", FSUtilities.appendPath("blah", "/sub"));
		assertEquals("blah\\sub", FSUtilities.appendPath("blah", "\\sub"));

		assertEquals("/blah/blah\\sub", FSUtilities.appendPath("/blah/blah", "\\sub"));
		assertEquals("\\blah\\blah\\sub", FSUtilities.appendPath("\\blah\\blah", "\\sub"));
		assertEquals("\\blah\\blah\\sub", FSUtilities.appendPath("\\blah\\blah\\", "\\sub"));
	}

	@Test
	public void testAppendPath_MultipleSeparators() {

		assertEquals("/blah////", FSUtilities.appendPath("/blah", "////"));
		assertEquals("/blah////leading", FSUtilities.appendPath("/blah/", "////leading"));

		assertEquals("///", FSUtilities.appendPath("//", "//"));
		assertEquals("\\\\\\", FSUtilities.appendPath("\\\\", "\\\\"));
	}

	@Test
	public void testGetExtension() {
		assertEquals(".ext", FSUtilities.getExtension("blah.ext", 1));
		assertEquals(".ext", FSUtilities.getExtension("blah.xyz.ext", 1));
		assertEquals(".", FSUtilities.getExtension("blah.", 1));
		assertNull(FSUtilities.getExtension("blah", 1));
		assertNull(FSUtilities.getExtension("blah.ext/filename", 1));

		assertEquals(".xyz.ext", FSUtilities.getExtension("blah.xyz.ext", 2));
		assertNull(FSUtilities.getExtension("blah.ext", 2));

		try {
			FSUtilities.getExtension("hi", 0);
		}
		catch (IllegalArgumentException e) {
			// good
		}
	}

}
