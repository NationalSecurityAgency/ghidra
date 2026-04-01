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
package ghidra.framework.protocol.ghidra;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.client.*;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.protocol.ghidra.GhidraURLConnection.StatusCode;

public class GhidraURLTest extends AbstractGenericTest {

	@Before
	public void setUp() throws Exception {
		Handler.registerHandler();
	}

	//	makeURL(ProjectLocator)
	@Test
	public void testMakeLocalProjectURL() throws Exception {
		ProjectLocator loc = new ProjectLocator("C:\\junk", "Test");
		assertEquals("/C:/junk/", loc.getLocation());
		assertTrue(loc.isWindowsOnlyLocation());
		URL ghidraUrl = GhidraURL.makeURL(loc);
		URL url = toGhidraLocalURL("/C:/junk/Test", null);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("C:\\junk\\", "Test");
		assertEquals("/C:/junk/", loc.getLocation());
		assertTrue(loc.isWindowsOnlyLocation());
		ghidraUrl = GhidraURL.makeURL(loc);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/C:/junk", "Test");
		assertEquals("/C:/junk/", loc.getLocation());
		assertTrue(loc.isWindowsOnlyLocation());
		ghidraUrl = GhidraURL.makeURL(loc);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/C:/junk/", "Test");
		assertEquals("/C:/junk/", loc.getLocation());
		assertTrue(loc.isWindowsOnlyLocation());
		ghidraUrl = GhidraURL.makeURL(loc);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/C:/junk/x y z/", "Test");
		assertEquals("/C:/junk/x y z/", loc.getLocation());
		assertTrue(loc.isWindowsOnlyLocation());
		ghidraUrl = GhidraURL.makeURL(loc);
		url = toGhidraLocalURL("/C:/junk/x y z/Test", null);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/a/b", "Test");
		assertEquals("/a/b/", loc.getLocation());
		assertFalse(loc.isWindowsOnlyLocation());
		ghidraUrl = GhidraURL.makeURL(loc);
		url = toGhidraLocalURL("/a/b/Test", null);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		// Unicode foreign language example
		loc = new ProjectLocator("/\u6771\u4EAC/\u30EC\u30B9\u30C8\u30E9\u30F3", "Gr\u00FCnerTee");
		assertEquals("/\u6771\u4EAC/\u30EC\u30B9\u30C8\u30E9\u30F3/", loc.getLocation());
		assertFalse(loc.isWindowsOnlyLocation());
		ghidraUrl = GhidraURL.makeURL(loc);
		url = toGhidraLocalURL("/\u6771\u4EAC/\u30EC\u30B9\u30C8\u30E9\u30F3/Gr\u00FCnerTee", null);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		// UNC path - limited support on Windows
		loc = new ProjectLocator("\\\\myserver\\myshare\\a\\b", "Test");
		assertEquals("//myserver/myshare/a/b/", loc.getLocation());
		assertTrue(loc.isWindowsOnlyLocation());
		ghidraUrl = GhidraURL.makeURL(loc);
		url = toGhidraLocalURL("////myserver/myshare/a/b/Test", null);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		// UNC path - limited support on Windows
		loc = new ProjectLocator("//a/b", "Test");
		assertEquals("//a/b/", loc.getLocation());
		assertTrue(loc.isWindowsOnlyLocation());
		ghidraUrl = GhidraURL.makeURL(loc);
		url = toGhidraLocalURL("////a/b/Test", null);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		try {
			new ProjectLocator("a/b", "Test");
			fail("relative path should not be permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			new ProjectLocator("\\\\", "Test");
			fail("incomplete network path should not be permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			new ProjectLocator("\\\\a\\", "Test");
			fail("incomplete network path should not be permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			new ProjectLocator("//", "Test");
			fail("incomplete network path should not be permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	//	makeURL(String, String)
	@Test
	public void testMakeLocalProjectURL2() throws Exception {
		ProjectLocator loc = new ProjectLocator("C:\\junk", "Test");
		URL ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test");
		URL url = toGhidraLocalURL("/C:/junk/Test", null);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("C:\\junk\\", "Test");
		ghidraUrl = GhidraURL.makeURL("C:\\junk\\", "Test");
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/C:/junk", "Test");
		ghidraUrl = GhidraURL.makeURL("/C:/junk", "Test");
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/C:/junk/", "Test");
		ghidraUrl = GhidraURL.makeURL("/C:/junk/", "Test");
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/a/b", "Test");
		ghidraUrl = GhidraURL.makeURL("/a/b", "Test");
		url = toGhidraLocalURL("/a/b/Test", null);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/a/b/", "Test");
		ghidraUrl = GhidraURL.makeURL("/a/b/", "Test");
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		// UNC path - limited support on Windows
		loc = new ProjectLocator("\\\\a\\b", "Test");
		ghidraUrl = GhidraURL.makeURL("\\\\a\\b", "Test");
		url = toGhidraLocalURL("////a/b/Test", null);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		// UNC path - limited support on Windows
		loc = new ProjectLocator("//a/b", "Test");
		ghidraUrl = GhidraURL.makeURL("//a/b", "Test");
		url = toGhidraLocalURL("////a/b/Test", null);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		try {
			GhidraURL.makeURL("a/b/", "Test");
			fail("relative path should not be permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			GhidraURL.makeURL("\\\\", "Test");
			fail("incomplete network path should not be permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			GhidraURL.makeURL("\\\\a\\", "Test");
			fail("incomplete network path should not be permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			GhidraURL.makeURL("//", "Test");
			fail("incomplete network path should not be permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	//	makeURL(ProjectLocator, String, String)
	@Test
	public void testMakeLocalProjectFileURL() throws Exception {
		ProjectLocator loc = new ProjectLocator("C:\\junk", "Test");

		URL ghidraUrl = GhidraURL.makeURL(loc, "/a", "ref");
		URL url = toGhidraLocalURL("/C:/junk/Test", "/a", "ref");
		assertEquals(url, ghidraUrl);
		assertEquals("ref", GhidraURL.getDecodedReference(ghidraUrl));
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));
		url = toGhidraLocalURL("/C:/junk/Test", "/a/", "ref");
		assertEquals(url, GhidraURL.getFolderURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL(loc, "/a/", "ref");
		url = toGhidraLocalURL("/C:/junk/Test", "/a/", "ref");
		assertEquals(url, ghidraUrl);
		assertEquals("ref", GhidraURL.getDecodedReference(ghidraUrl));
		assertEquals(url, GhidraURL.getFolderURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL(loc, "/a/x y z/", "ref");
		url = toGhidraLocalURL("/C:/junk/Test", "/a/x y z/", "ref");
		assertEquals(url, ghidraUrl);
		assertEquals("ref", GhidraURL.getDecodedReference(ghidraUrl));
		assertEquals(url, GhidraURL.getFolderURL(ghidraUrl));

		// UNC project path - limited support on Windows
		loc = new ProjectLocator("\\\\server\\share\\junk", "Test");

		ghidraUrl = GhidraURL.makeURL(loc, "/a", "ref");
		url = toGhidraLocalURL("////server/share/junk/Test", "/a", "ref");
		assertEquals(url, ghidraUrl);
		assertEquals("ref", GhidraURL.getDecodedReference(ghidraUrl));
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));
		url = toGhidraLocalURL("////server/share/junk/Test", "/a/", "ref");
		assertEquals(url, GhidraURL.getFolderURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL(loc, "/a/", "ref");
		url = toGhidraLocalURL("////server/share/junk/Test", "/a/", "ref");
		assertEquals(url, ghidraUrl);
		assertEquals("ref", GhidraURL.getDecodedReference(ghidraUrl));
		assertEquals(url, GhidraURL.getFolderURL(ghidraUrl));

		try {
			GhidraURL.makeURL(loc, "a/b", "ref");
			fail("relative path should not be permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	//	makeURL(String, String, String, String)
	@Test
	public void testMakeLocalProjectFileURL2() throws Exception {
		ProjectLocator loc = new ProjectLocator("C:\\junk", "Test");

		URL ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a", "ref");
		URL url = toGhidraLocalURL("/C:/junk/Test", "/a", "ref");
		assertEquals(url, ghidraUrl);
		assertEquals("ref", GhidraURL.getDecodedReference(ghidraUrl));
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a/", "ref");
		url = toGhidraLocalURL("/C:/junk/Test", "/a/", "ref");
		assertEquals(url, ghidraUrl);
		assertEquals("ref", GhidraURL.getDecodedReference(ghidraUrl));

		// Unicode foreign language example
		ghidraUrl = GhidraURL.makeURL("C:\\\u6771\u4EAC", "Gr\u00FCnerTee",
			"/\u30EC\u30B9\u30C8\u30E9\u30F3/", "caf\u00E9-menu");
		url = toGhidraLocalURL("/C:/\u6771\u4EAC/Gr\u00FCnerTee",
			"/\u30EC\u30B9\u30C8\u30E9\u30F3/", "caf\u00E9-menu");
		assertEquals(url, ghidraUrl);
		assertEquals("caf\u00E9-menu", GhidraURL.getDecodedReference(ghidraUrl));

		try {
			ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "a/b", "ref");
			fail("relative path should not be permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

//	makeURL(String, String, String, String)
	@Test
	public void testMakeLocalProjectFileURL3() throws Exception {
		ProjectLocator loc = new ProjectLocator("C:\\junk\\test.-=@ _()[]", "Test.-=@ _()[]");

		// The ref field must allow pretty much any character

		URL ghidraUrl = GhidraURL.makeURL("C:\\junk\\test.-=@ _()[]", "Test.-=@ _()[]",
			"/a.-=@ _()[]", "ref .-=@ _()[]~!@#$%^&*+<>?/\\,`|\'\"");

		URL url = toGhidraLocalURL("/C:/junk/test.-=@ _()[]/Test.-=@ _()[]", "/a.-=@ _()[]",
			"ref .-=@ _()[]~!@#$%^&*+<>?/\\,`|\'\"");
		assertEquals(url, ghidraUrl);
		assertEquals("ref .-=@ _()[]~!@#$%^&*+<>?/\\,`|\'\"",
			GhidraURL.getDecodedReference(ghidraUrl));
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		try {
			GhidraURL.makeURL("C:\\junk\\test+", "Test", "/a", "ref");
			fail("The '+' character is not permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			GhidraURL.makeURL("C:\\junk\\test", "Test+", "/a", "ref");
			fail("The '+' character is not permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			GhidraURL.makeURL("C:\\junk\\test", "Test", "/a+", "ref");
			fail("The '+' character is not permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

	}

	//	makeURL(String, int)
	@Test
	public void testMakeServerURL() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("localhost", 123);
		URL url = toGhidraServerURL("localhost", 123, null, null);
		assertEquals(url, ghidraUrl);
	}

	//	makeURL(String, int, String)
	@Test
	public void testMakeServerRepoURL() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test");
		URL url = toGhidraServerURL("localhost", 123, "Test", null);
		assertEquals(url, ghidraUrl);
	}

	//	makeURL(String, int, String, String)
	@Test
	public void testMakeServerRepoFileURL() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/");
		URL url = toGhidraServerURL("localhost", 123, "Test", "/foo/");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo");
		url = toGhidraServerURL("localhost", 123, "Test", "/foo");
		assertEquals(url, ghidraUrl);

	}

	//	makeURL(String, int, String, String, String, String)
	@Test
	public void testMakeServerRepoFileURL2() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/", "foo", null);
		URL url = toGhidraServerURL("localhost", 123, "Test", "/foo");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/", "foo/", null);
		url = toGhidraServerURL("localhost", 123, "Test", "/foo/");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo", "bar", "ref");
		url = toGhidraServerURL("localhost", 123, "Test", "/foo/bar", "ref");
		assertEquals(url, ghidraUrl);
		assertEquals("ref", GhidraURL.getDecodedReference(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/", "bar", "ref");
		assertEquals(url, ghidraUrl);
		assertEquals("ref", GhidraURL.getDecodedReference(ghidraUrl));

		// Unicode foreign language example
		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Gr\u00FCnerTee", "/\u6771\u4EAC/",
			"\u30EC\u30B9\u30C8\u30E9\u30F3", "caf\u00E9-menu");
		url = toGhidraServerURL("localhost", 123, "Gr\u00FCnerTee",
			"/\u6771\u4EAC/\u30EC\u30B9\u30C8\u30E9\u30F3", "caf\u00E9-menu");
		assertEquals(url, ghidraUrl);
		assertEquals("caf\u00E9-menu", GhidraURL.getDecodedReference(ghidraUrl));
	}

//	makeURL(String, int, String, String)
	@Test
	public void testMakeServerRepoFileURL3() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo");
		URL url = toGhidraServerURL("localhost", 123, "Test", "/foo");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/");
		url = toGhidraServerURL("localhost", 123, "Test", "/foo/");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/bar", "ref");
		url = toGhidraServerURL("localhost", 123, "Test", "/foo/bar", "ref");
		assertEquals(url, ghidraUrl);
		assertEquals("ref", GhidraURL.getDecodedReference(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/bar");
		url = toGhidraServerURL("localhost", 123, "Test", "/foo/bar");
		assertEquals(url, ghidraUrl);
	}

//	makeURL(String, int, String, String)
	@Test
	public void testMakeServerRepoFileURL4() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test.-=@ _()[]", "/foo.-=@ _()[]");
		URL url = toGhidraServerURL("localhost", 123, "Test.-=@ _()[]", "/foo.-=@ _()[]");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test.-=@ _()[]", "/foo.-=@ _()[]/");
		url = toGhidraServerURL("localhost", 123, "Test.-=@ _()[]", "/foo.-=@ _()[]/");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test.-=@ _()[]", "/foo/bar.-=@ _()[]",
			"ref .-=@ _()[]~!@#$%^&*+<>?/\\,`|\'\"");
		url = toGhidraServerURL("localhost", 123, "Test.-=@ _()[]", "/foo/bar.-=@ _()[]",
			"ref .-=@ _()[]~!@#$%^&*+<>?/\\,`|\'\"");
		assertEquals(url, ghidraUrl);
		assertEquals("ref .-=@ _()[]~!@#$%^&*+<>?/\\,`|\'\"",
			GhidraURL.getDecodedReference(ghidraUrl));

		try {
			GhidraURL.makeURL("localhost", 123, "Test+", "/foo");
			fail("The '+' character is not permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			GhidraURL.makeURL("localhost", 123, "Test", "/foo+");
			fail("The '+' character is not permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	//	getProjectStorageLocator(URL)
	@Test
	public void testGetProjectStorageLocator() throws Exception {
		ProjectLocator loc = new ProjectLocator("C:\\junk", "Test");
		URL ghidraUrl = GhidraURL.makeURL(loc);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("C:\\junk\\", "Test");
		ghidraUrl = GhidraURL.makeURL(loc);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/C:/junk", "Test");
		ghidraUrl = GhidraURL.makeURL(loc);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/C:/junk/", "Test");
		ghidraUrl = GhidraURL.makeURL(loc);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/a/b", "Test");
		ghidraUrl = GhidraURL.makeURL(loc);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/a/b/", "Test");
		ghidraUrl = GhidraURL.makeURL(loc);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));
	}

	//	isLocalURL(URL)
	@Test
	public void testIsLocalProjectURL() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test");
		assertTrue(GhidraURL.isLocalURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a", "ref");
		assertTrue(GhidraURL.isLocalURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("/x/y", "Test", "/a", "ref");
		assertTrue(GhidraURL.isLocalURL(ghidraUrl));

		// Windows UNC path
		ghidraUrl = GhidraURL.makeURL("\\\\a\\b", "Test");
		assertTrue(GhidraURL.isLocalURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test");
		assertFalse(GhidraURL.isLocalURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/", "bar", "ref");
		assertFalse(GhidraURL.isLocalURL(ghidraUrl));
	}

	//	isServerRepositoryURL(URL)
	@Test
	public void testIsServerRepositoryURL() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test");
		assertNull(GhidraURL.getRepositoryName(ghidraUrl));
		assertFalse(GhidraURL.isServerRepositoryURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a", "ref");
		assertNull(GhidraURL.getRepositoryName(ghidraUrl));
		assertFalse(GhidraURL.isServerRepositoryURL(ghidraUrl));

		// Windows UNC path
		ghidraUrl = GhidraURL.makeURL("\\\\a\\b", "Test");
		assertNull(GhidraURL.getRepositoryName(ghidraUrl));
		assertFalse(GhidraURL.isServerRepositoryURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("/x/y", "Test", "/a", "ref");
		assertNull(GhidraURL.getRepositoryName(ghidraUrl));
		assertFalse(GhidraURL.isServerRepositoryURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test");
		assertEquals("Test", GhidraURL.getRepositoryName(ghidraUrl));
		assertTrue(GhidraURL.isServerRepositoryURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/", "bar", "ref");
		assertEquals("Test", GhidraURL.getRepositoryName(ghidraUrl));
		assertTrue(GhidraURL.isServerRepositoryURL(ghidraUrl));

		ghidraUrl = toGhidraServerURL("localhost", 123, "", null);
		assertNull(GhidraURL.getRepositoryName(ghidraUrl));
		assertFalse(GhidraURL.isServerRepositoryURL(ghidraUrl));
	}

	//	isServerURL(URL)
	@Test
	public void testIsServerURL() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a", "ref");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:\\", "Test");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:\\", "Test", "/a", "ref");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:", "Test");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:", "Test", "/a", "ref");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("/c:/junk", "Test");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("/c:/junk", "Test", "/a", "ref");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("/c:/", "Test");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("/c:/", "Test", "/a", "ref");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("/c:", "Test");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("/c:", "Test", "/a", "ref");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		// Windows UNC path
		ghidraUrl = GhidraURL.makeURL("\\\\a\\b", "Test");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("/x/y", "Test", "/a", "ref");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test");
		assertTrue(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/", "bar", "ref");
		assertTrue(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = toGhidraServerURL("localhost", 123, "", null);
		assertTrue(GhidraURL.isServerURL(ghidraUrl));
	}

	//	toURL(String)
	@Test
	public void testToURL() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test");
		assertEquals(ghidraUrl, GhidraURL.toURL("C:\\junk\\Test"));
		assertEquals(ghidraUrl, GhidraURL.toURL("/C:/junk/Test"));
		assertEquals(ghidraUrl, GhidraURL.toURL("C:/junk/Test"));
		assertEquals(ghidraUrl, GhidraURL.toURL("ghidra:/C:/junk/Test"));
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a", "ref");
		assertEquals(ghidraUrl, GhidraURL.toURL("ghidra:/C:/junk/Test?/a#ref"));
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));
		assertEquals("ref", GhidraURL.getDecodedReference(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a/", "ref");
		assertEquals(ghidraUrl, GhidraURL.toURL("ghidra:/C:/junk/Test?/a/#ref"));
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));

		// Windows UNC path
		ghidraUrl = GhidraURL.makeURL("\\\\a\\b", "Test", "/a", "ref");
		assertEquals(ghidraUrl, GhidraURL.toURL("ghidra:////a/b/Test?/a#ref"));
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));

		// Windows UNC path
		ghidraUrl = GhidraURL.makeURL("\\\\a\\b", "Test", "/a/", "ref");
		assertEquals(ghidraUrl, GhidraURL.toURL("ghidra:////a/b/Test?/a/#ref"));
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));

		ghidraUrl = GhidraURL.makeURL("/x/y", "Test", "/a/", "ref");
		assertEquals(ghidraUrl, GhidraURL.toURL("ghidra:/x/y/Test?/a/#ref"));
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));
		assertEquals("ref", GhidraURL.getDecodedReference(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo", "bar", "ref+123");
		// GhidraURL.toURL requires external URL form with double-encoding for '+' in ref
		assertEquals(ghidraUrl, GhidraURL.toURL("ghidra://localhost:123/Test/foo/bar#ref%252B123"));
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));

		// Unicode foreign language example
		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Gr\u00FCnerTee", "/\u6771\u4EAC/",
			"\u30EC\u30B9\u30C8\u30E9\u30F3", "caf\u00E9-menu");
		assertEquals(ghidraUrl, GhidraURL.toURL(
			"ghidra://localhost:123/Gr\u00FCnerTee/\u6771\u4EAC/\u30EC\u30B9\u30C8\u30E9\u30F3#caf\u00E9-menu"));
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));
	}

	@Test
	public void testGetProjectURL() throws Exception {

		URL ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test");
		assertEquals(toGhidraLocalURL("/C:/junk/Test", null), GhidraURL.getProjectURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a", "ref");
		assertEquals(toGhidraLocalURL("/C:/junk/Test", null), GhidraURL.getProjectURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("/x/y", "Test", "/a", "ref");
		assertEquals(toGhidraLocalURL("/x/y/Test", null), GhidraURL.getProjectURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test");
		assertEquals(toGhidraServerURL("localhost", 123, "Test", null),
			GhidraURL.getProjectURL(ghidraUrl));
		assertEquals(toGhidraServerURL("localhost", 123, "Test", null), ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/", "bar", "ref");
		assertEquals(toGhidraServerURL("localhost", 123, "Test", null),
			GhidraURL.getProjectURL(ghidraUrl));
		assertEquals(toGhidraServerURL("localhost", 123, "Test", "/foo/bar", "ref"), ghidraUrl);

		ghidraUrl = toGhidraServerURL("localhost", 123, "", null);
		try {
			GhidraURL.getProjectURL(ghidraUrl);
			fail("Expected IllegalArgumentException");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	//	getDisplayString(URL)
	@Test
	public void testGetDisplayString() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test");
		assertEquals("C:\\junk\\Test", GhidraURL.getDisplayString(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a", "ref");
		assertEquals("ghidra:/C:/junk/Test?/a#ref", GhidraURL.getDisplayString(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a/", "ref");
		assertEquals("ghidra:/C:/junk/Test?/a/#ref", GhidraURL.getDisplayString(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("/x/y", "Test", "/a/", "ref");
		assertEquals("ghidra:/x/y/Test?/a/#ref", GhidraURL.getDisplayString(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo", "bar", "ref");
		assertEquals(ghidraUrl.toString(), GhidraURL.getDisplayString(ghidraUrl));

	}

	//	getNormalizedURL(URL)
	@Test
	public void testNormalizedURL() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test");
		assertEquals("ghidra:/C:/junk/Test", GhidraURL.getNormalizedURL(ghidraUrl).toString());

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a", "ref");
		assertEquals("ghidra:/C:/junk/Test?/a", GhidraURL.getNormalizedURL(ghidraUrl).toString());

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a/", "ref");
		assertEquals("ghidra:/C:/junk/Test?/a/", GhidraURL.getNormalizedURL(ghidraUrl).toString());

		ghidraUrl = GhidraURL.makeURL("/x/y", "Test", "/a/", "ref");
		assertEquals("ghidra:/x/y/Test?/a/", GhidraURL.getNormalizedURL(ghidraUrl).toString());

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo", "bar", "ref");
		assertEquals("ghidra://127.0.0.1:123/Test/foo/bar",
			GhidraURL.getNormalizedURL(ghidraUrl).toString());
	}

	@Test
	public void testTransientProjectURL() throws Exception {
		// Dummy class implementations (see below) are used to stub objects required to establish 
		// transient project for URL verification testing only
		URL ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test");
		DummyGhidraProtocolConnector dummyRepoConnector =
			new DummyGhidraProtocolConnector(ghidraUrl);
		TransientProjectManager transientProjectManager =
			TransientProjectManager.getTransientProjectManager();
		try {
			TransientProjectData transientProject =
				transientProjectManager.getTransientProject(dummyRepoConnector, true);
			ProjectLocator projectLocator = transientProject.getProjectLocator();
			assertTrue(GhidraURL.isServerRepositoryURL(projectLocator.getURL()));

			// Transient project will result in server URL
			URL serverUrl = GhidraURL.makeURL(projectLocator, "/a/b/c", "ref");
			URL url = toGhidraServerURL("localhost", 123, "Test", "/a/b/c", "ref");
			assertEquals(url, serverUrl);
		}
		finally {
			transientProjectManager.dispose();
		}
	}

	@Test
	public void testResolve() {
		
		URL ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test");
		assertEquals(GhidraURL.makeURL("C:\\junk", "Test", "/a/b", "ref"),
			GhidraURL.resolve(ghidraUrl, "/a/b", "ref"));

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a", "ref");
		assertEquals(GhidraURL.makeURL("C:\\junk", "Test", "/x/y/", "refX"),
			GhidraURL.resolve(ghidraUrl, "/x/y/", "refX"));

		// Windows UNC path
		ghidraUrl = GhidraURL.makeURL("\\\\a\\b", "Test");
		assertEquals(GhidraURL.makeURL("\\\\a\\b", "Test", "/x/y", "ref"),
			GhidraURL.resolve(ghidraUrl, "/x/y", "ref"));

		ghidraUrl = GhidraURL.makeURL("/x/y", "Test", "/a", "ref");
		assertEquals(GhidraURL.makeURL("/x/y", "Test", "/x/y/", "refX"),
			GhidraURL.resolve(ghidraUrl, "/x/y/", "refX"));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test");
		assertEquals(GhidraURL.makeURL("localhost", 123, "Test", "/x/y/", "ref"),
			GhidraURL.resolve(ghidraUrl, "/x/y/", "ref"));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/", "bar", "ref");
		assertEquals(GhidraURL.makeURL("localhost", 123, "Test", "/x/y/", "refX"),
			GhidraURL.resolve(ghidraUrl, "/x/y/", "refX"));

	}

	private static class DummyGhidraProtocolConnector extends GhidraProtocolConnector {

		private URL repositoryURL;
		private DummyRepositoryAdapter repoAdapter;

		DummyGhidraProtocolConnector(URL repositoryURL) throws MalformedURLException {
			super(repositoryURL);
			this.repositoryURL = repositoryURL;
			repoAdapter = new DummyRepositoryAdapter();
		}

		@Override
		protected URL getRepositoryRootGhidraURL() {
			return repositoryURL;
		}

		@Override
		public StatusCode connect(boolean readOnly) throws IOException {
			return StatusCode.OK;
		}

		@Override
		public boolean isReadOnly() throws NotConnectedException {
			return true;
		}

		@Override
		public RepositoryAdapter getRepositoryAdapter() {
			return repoAdapter;
		}

	}

	private static class DummyRepositoryAdapter extends RepositoryAdapter {
		DummyRepositoryAdapter() {
			super(new DummyRepositoryServerAdapter(), "test");
		}

		@Override
		public boolean isConnected() {
			return true;
		}
	}

	private static class DummyRepositoryServerAdapter extends RepositoryServerAdapter {
		DummyRepositoryServerAdapter() {
			super(null, null);
		}
	}

	private URL toGhidraLocalURL(String path, String projectFilePath)
			throws MalformedURLException, URISyntaxException {
		return new URI(GhidraURL.PROTOCOL, null, path, projectFilePath, null).toURL();
	}

	private URL toGhidraLocalURL(String path, String projectFilePath, String ref)
			throws MalformedURLException, URISyntaxException {
		if (ref != null) {
			ref = ref.replace("+", "%2B"); // force encoding of "+"
		}
		return new URI(GhidraURL.PROTOCOL, null, path, projectFilePath, ref).toURL();
	}

	private URL toGhidraServerURL(String host, int port, String repo, String path)
			throws MalformedURLException, URISyntaxException {
		if (repo == null && path == null) {
			return new URI(GhidraURL.PROTOCOL, null, host, port, null, null, null).toURL();
		}
		return toGhidraServerURL(host, port, repo, path, null);
	}

	private URL toGhidraServerURL(String host, int port, String repo, String path, String ref)
			throws MalformedURLException, URISyntaxException {
		String repoAndPath = "/" + repo;
		if (path != null) {
			repoAndPath += path;
		}
		if (ref != null) {
			ref = ref.replace("+", "%2B"); // force encoding of "+"
		}
		return new URI(GhidraURL.PROTOCOL, null, host, port, repoAndPath, null, ref).toURL();
	}
}
