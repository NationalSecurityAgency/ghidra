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

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.*;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.client.*;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.protocol.ghidra.GhidraURLConnection.StatusCode;
import ghidra.util.NamingUtilities;

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

		StringBuilder specialChars = new StringBuilder();
		for (Character c : NamingUtilities.VALID_NAME_CHARSET) {
			specialChars.append(c);
		}

		loc = new ProjectLocator("/a/b" + specialChars, "Test" + specialChars);
		assertEquals("/a/b" + specialChars + "/", loc.getLocation());
		assertFalse(loc.isWindowsOnlyLocation());
		ghidraUrl = GhidraURL.makeURL(loc);
		url = toGhidraLocalURL("/a/b" + specialChars + "/Test" + specialChars, null);
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
		ProjectLocator loc = new ProjectLocator("C:\\junk\\test.-=@ _()[]+", "Test.-=@ _()[]+");

		// The ref field must allow pretty much any character

		URL ghidraUrl = GhidraURL.makeURL("C:\\junk\\test.-=@ _()[]+", "Test.-=@ _()[]+",
			"/a.-=@ _()[]+", "ref .-=@ _()[]~!@#$%^&*+<>?/\\,`|\'\"");

		URL url = toGhidraLocalURL("/C:/junk/test.-=@ _()[]+/Test.-=@ _()[]+", "/a.-=@ _()[]+",
			"ref .-=@ _()[]~!@#$%^&*+<>?/\\,`|\'\"");
		assertEquals(url, ghidraUrl);
		assertEquals("ref .-=@ _()[]~!@#$%^&*+<>?/\\,`|\'\"",
			GhidraURL.getDecodedReference(ghidraUrl));
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));
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
		URL ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test.-=@ _()[]+", "/foo.-=@ _()[]+");
		URL url = toGhidraServerURL("localhost", 123, "Test.-=@ _()[]+", "/foo.-=@ _()[]+");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test.-=@ _()[]+", "/foo.-=@ _()[]+/");
		url = toGhidraServerURL("localhost", 123, "Test.-=@ _()[]+", "/foo.-=@ _()[]+/");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test.-=@ _()[]+", "/foo/bar.-=@ _()[]+",
			"ref .-=@ _()[]~!@#$%^&*+<>?/\\,`|\'\"");
		url = toGhidraServerURL("localhost", 123, "Test.-=@ _()[]+", "/foo/bar.-=@ _()[]+",
			"ref .-=@ _()[]~!@#$%^&*+<>?/\\,`|\'\"");
		assertEquals(url, ghidraUrl);
		assertEquals("ref .-=@ _()[]~!@#$%^&*+<>?/\\,`|\'\"",
			GhidraURL.getDecodedReference(ghidraUrl));

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

	@Test
	public void testBadServerURL() throws Exception {

		try {
			GhidraURL.toURL("ghidra://localhost:123/Test/foo/bar?/a/b#ref%20+123");
			fail("Expected failure due to invalid query");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		URL url = URI.create("ghidra://localhost:123/Test/foo/bar?/a/b#ref%20+123").toURL();

		try {
			GhidraURL.getRepositoryName(url);
			fail("Expected failure due to invalid query");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			GhidraURL.getFolderURL(url);
			fail("Expected failure due to invalid query");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			GhidraURL.getNormalizedURL(url);
			fail("Expected failure due to invalid query");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			GhidraURL.getProjectPathname(url);
			fail("Expected failure due to invalid query");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			GhidraURL.getProjectURL(url);
			fail("Expected failure due to invalid query");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testToURLShortProjectPaths() {
		assertEquals(GhidraURL.makeURL("/", "a").toExternalForm(),
			GhidraURL.toURL("/a").toExternalForm());
		assertEquals(GhidraURL.makeURL("/", "a").toExternalForm(),
			GhidraURL.toURL("\\a").toExternalForm());
		assertEquals(GhidraURL.makeURL("C:/", "a").toExternalForm(),
			GhidraURL.toURL("C:/a").toExternalForm());
	}

	@Test
	public void testToURLRejectsMissingProjectName() {
		for (String path : new String[] { "/", "\\", "C:", "C:/", "/C:/", "/projects/" }) {
			IllegalArgumentException exception = assertThrows(path, IllegalArgumentException.class,
				() -> GhidraURL.toURL(path));
			assertEquals("Absolute project path is missing project name", exception.getMessage());
		}
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

		ghidraUrl = GhidraURL.makeURL("/x/y", "Test", "/a/", "ref +123");
		assertEquals("ref%20+123", ghidraUrl.getRef());
		assertEquals("ref +123", ghidraUrl.toURI().getFragment());

		assertEquals(ghidraUrl, GhidraURL.toURL("ghidra:/x/y/Test?/a/#ref%20+123"));
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));
		assertEquals("ref +123", GhidraURL.getDecodedReference(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo", "bar", "ref +123");
		assertEquals("ref%20+123", ghidraUrl.getRef());
		assertEquals("ref +123", ghidraUrl.toURI().getFragment());

		assertEquals(ghidraUrl, GhidraURL.toURL("ghidra://localhost:123/Test/foo/bar#ref%20+123"));
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));
		assertEquals("ref +123", GhidraURL.getDecodedReference(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo", "bar", "ref++123");
		assertEquals("ref++123", ghidraUrl.getRef());
		assertEquals("ref++123", ghidraUrl.toURI().getFragment());

		assertEquals(ghidraUrl, GhidraURL.toURL("ghidra://localhost:123/Test/foo/bar#ref++123"));
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));
		assertEquals("ref++123", GhidraURL.getDecodedReference(ghidraUrl));

		// Unicode foreign language example
		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Gr\u00FCnerTee", "/\u6771\u4EAC/",
			"\u30EC\u30B9\u30C8\u30E9\u30F3", "caf\u00E9-menu");
		assertEquals(ghidraUrl, GhidraURL.toURL(
			"ghidra://localhost:123/Gr\u00FCnerTee/\u6771\u4EAC/\u30EC\u30B9\u30C8\u30E9\u30F3#caf\u00E9-menu"));
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));
	}

	@Test
	public void testLocalProjectMarkerCompatibility() throws Exception {
		for (String location : new String[] { "/projects", "C:/projects", "//server/share" }) {
			// This branch accepts marker filenames in ProjectLocator, but not in toURL paths.
			ProjectLocator locator = new ProjectLocator(location, "Test.gpr");
			assertEquals("Test", locator.getName());
			URL url = GhidraURL.makeURL(location, "Test");
			assertEquals(url.toExternalForm(), locator.getURL().toExternalForm());
			assertEquals(locator, GhidraURL.getProjectStorageLocator(url));
			assertEquals(url.toExternalForm(),
				GhidraURL.toURL(location + "/Test").toExternalForm());
			assertEquals(url.toExternalForm(),
				GhidraURL.toURL(GhidraURL.getDisplayString(url)).toExternalForm());
			for (String name : new String[] { "Test.gpr", "Test.rep", "Test.gpr.gpr", ".gpr" }) {
				assertThrows(IllegalArgumentException.class,
					() -> GhidraURL.toURL(location + "/" + name));
			}

			// Explicit URL parsing retains its encoding; locator interpretation strips the marker.
			URL markerURL = GhidraURL.makeURL(location, "Test.gpr", "/folder/file", "ref");
			assertEquals(markerURL.toExternalForm(),
				GhidraURL.toURL(markerURL.toExternalForm()).toExternalForm());
			assertEquals(locator, GhidraURL.getProjectStorageLocator(markerURL));
			assertEquals("Test",
				new DefaultLocalGhidraProtocolConnector(markerURL).getRepositoryName());
		}
	}

	@Test
	public void testToURLRejectsInvalidDecodedComponents() {
		String[] invalid = { "bad%3Fname", "bad%2Aname", "bad%3Aname", "bad%5Cname",
			"bad%00name", "%20", "%2E", "%2E%2E", "%2Ehidden", "bad%23name",
			"bad%2520name", "bad%252Fname", "bad%26name", "bad%C2%A9name", "a//b", "a//" };
		for (String component : invalid) {
			for (String text : new String[] {
				"ghidra:/projects/" + component,
				"ghidra:/" + component + "/Project",
				"ghidra:/projects/Project?/" + component,
				"ghidra://localhost/" + component,
				"ghidra://localhost/Repo/" + component }) {
				assertThrows(text, IllegalArgumentException.class, () -> GhidraURL.toURL(text));
			}
		}
		for (String text : new String[] { "ghidra:/", "ghidra:/projects/",
			"ghidra:/projects/Project?relative", "ghidra:/projects/Project?",
			"ghidra:/projects/Project?//", "ghidra://localhost//Repo",
			"ghidra:/projects/Project?/bad name*", "ghidra://localhost/Repo/bad name*" }) {
			assertThrows(text, IllegalArgumentException.class, () -> GhidraURL.toURL(text));
		}
	}

	@Test
	public void testToURLPreservesEncodedComponents() throws Exception {
		String name = "name + [a] 東京 \uD801\uDC00";
		for (String path : new String[] { null, "/", "/" + name, "/" + name + "/" }) {
			for (URL url : new URL[] {
				GhidraURL.makeURL("/projects", name, path, "ref #?%20+"),
				GhidraURL.makeURL("C:/projects", name, path, "ref #?%20+"),
				GhidraURL.makeURL("//server/share", name, path, "ref #?%20+"),
				GhidraURL.makeURL("localhost", 123, name, path, "ref #?%20+") }) {
				String text = url.toURI().toASCIIString();
				URL parsed = GhidraURL.toURL(text);
				assertEquals(text, parsed.toExternalForm());
				assertEquals(path == null ? "/" : path, GhidraURL.getProjectPathname(parsed));
				assertEquals("ref #?%20+", GhidraURL.getDecodedReference(parsed));
			}
		}
		for (String text : new String[] { "ghidra://localhost", "ghidra://localhost:123/" }) {
			assertEquals(text, GhidraURL.toURL(text).toExternalForm());
		}
	}

	@Test
	public void testToURLValidatesExtensionComponents() throws Exception {
		for (String path : new String[] { "/Repo/bad*name", "/Repo/../file", "/Repo/a//" }) {
			URI inner = new URI("https", null, "localhost", 123, path, null, null);
			String text = new URI("ghidra", inner.toString(), null).toString();
			assertThrows(text, IllegalArgumentException.class, () -> GhidraURL.toURL(text));
		}
		URI inner = new URI("https", null, "localhost", 123, "/Repo [a]/folder +/",
			null, null);
		String text = new URI("ghidra", inner.toString(), "ref #?").toString();
		assertEquals(text, GhidraURL.toURL(text).toExternalForm());
	}

	@Test
	public void testRelaxedToURL() throws Exception {
		String path = "/Test/my foo/bar";
		String improperUrl = "ghidra://127.0.0.1:123" + path + "#a b+c";
		URL ghidraUrl = GhidraURL.toURL(improperUrl);

		assertEquals("a b+c", GhidraURL.getDecodedReference(ghidraUrl));
		assertEquals("Test", GhidraURL.getRepositoryName(ghidraUrl));
		assertEquals("/my foo/bar", GhidraURL.getProjectPathname(ghidraUrl));

		assertEquals(path.replace(" ", "%20"), ghidraUrl.getPath());
		assertEquals(null, ghidraUrl.getQuery());
		assertEquals("a%20b+c", ghidraUrl.getRef());

		improperUrl = "ghidra:" + path + "?" + path + "#a b+c";
		ghidraUrl = GhidraURL.toURL(improperUrl);

		assertEquals("a b+c", GhidraURL.getDecodedReference(ghidraUrl));
		assertEquals(path.replace('/', File.separatorChar) + ".rep",
			GhidraURL.getProjectStorageLocator(ghidraUrl).getProjectDir().toString());
		assertEquals(path, GhidraURL.getProjectPathname(ghidraUrl));

		assertEquals(path.replace(" ", "%20"), ghidraUrl.getPath());
		assertEquals(path.replace(" ", "%20"), ghidraUrl.getQuery());
		assertEquals("a%20b+c", ghidraUrl.getRef());
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

	@Test
	public void testBuildersRejectEmptyContentPathElements() throws Exception {
		ProjectLocator locator = new ProjectLocator("/projects", "Test");
		URL local = locator.getURL();
		URL server = GhidraURL.makeURL("localhost", 123, "Test");
		for (String path : new String[] { "//", "///", "/a//", "/a///", "/a/b//",
			"//a", "/a//b", "/a//b/" }) {
			assertThrows(path, IllegalArgumentException.class,
				() -> GhidraURL.makeURL("/projects", "Test", path, null));
			assertThrows(path, IllegalArgumentException.class,
				() -> GhidraURL.makeURL(locator, path, null));
			assertThrows(path, IllegalArgumentException.class,
				() -> GhidraURL.makeURL("localhost", 123, "Test", path));
			assertThrows(path, IllegalArgumentException.class,
				() -> GhidraURL.makeURL("localhost", 123, "Test", path, "ref"));
			assertThrows(path, IllegalArgumentException.class,
				() -> GhidraURL.resolve(local, path, null));
			assertThrows(path, IllegalArgumentException.class,
				() -> GhidraURL.resolve(server, path, null));

			// The connectors reject these same structures when supplied as raw URLs.
			URL rawLocal = toGhidraLocalURL("/projects/Test", path);
			URL rawServer = toGhidraServerURL("localhost", 123, "Test", path);
			assertThrows(path, MalformedURLException.class,
				() -> new DefaultLocalGhidraProtocolConnector(rawLocal));
			assertThrows(path, MalformedURLException.class,
				() -> new DefaultGhidraProtocolConnector(rawServer));
		}
		assertThrows(IllegalArgumentException.class,
			() -> GhidraURL.makeURL("localhost", 123, "Test", "/a//", "file", null));
		assertThrows(IllegalArgumentException.class,
			() -> GhidraURL.makeURL("localhost", 123, "Test", "/a", "file//", null));
	}

	@Test
	public void testBuildersPreserveValidContentPathStructure() throws Exception {
		ProjectLocator locator = new ProjectLocator("/projects", "Test");
		URL server = GhidraURL.makeURL("localhost", 123, "Test");
		for (String path : new String[] { null, "", "/", "/a", "/a/", "/a/b", "/a/b/" }) {
			String expectedPath = path == null || path.isEmpty() ? "/" : path;
			URL localURL = GhidraURL.makeURL("/projects", "Test", path, null);
			URL serverURL = GhidraURL.makeURL("localhost", 123, "Test", path);
			assertEquals(localURL.toExternalForm(),
				GhidraURL.makeURL(locator, path, null).toExternalForm());
			assertEquals(serverURL.toExternalForm(),
				GhidraURL.resolve(server, path, null).toExternalForm());
			for (URL url : new URL[] { localURL, serverURL }) {
				assertEquals(expectedPath, GhidraURL.getProjectPathname(url));
				GhidraProtocolConnector connector = GhidraURL.isLocalURL(url)
						? new DefaultLocalGhidraProtocolConnector(url)
						: new DefaultGhidraProtocolConnector(url);
				assertEquals(expectedPath, getInstanceField("itemPath", connector));
				if (expectedPath.endsWith("/")) {
					assertNull(connector.getFolderItemName());
				}
			}
		}
	}

	@Test
	public void testLocalStoragePathsRejectRepeatedSeparators() {
		for (String path : new String[] { "/projects//", "/projects///", "/a//b",
			"C:/projects//", "//server/share//" }) {
			assertThrows(path, IllegalArgumentException.class,
				() -> GhidraURL.checkLocalAbsolutePath(path, true));
		}
		assertEquals("/", GhidraURL.checkLocalAbsolutePath("/", true));
		assertEquals("/C:/", GhidraURL.checkLocalAbsolutePath("C:/", true));
		assertEquals("//server/share/",
			GhidraURL.checkLocalAbsolutePath("//server/share/", true));
	}

	@Test
	public void testResolveSpacesInServerPath() throws Exception {
		// Reproduce getSharedProjectURL: resolve a decoded file path against its folder URL.
		URL base = GhidraURL.makeURL("localhost", 123, "Repository", "/");
		URL url = GhidraURL.resolve(base, "/Sample Program.exe", null);
		String expected = "ghidra://localhost:123/Repository/Sample%20Program.exe";
		assertEquals(expected, url.toExternalForm());
		assertEquals("/Repository/Sample%20Program.exe", url.getPath());
		assertEquals("/Repository/Sample Program.exe", url.toURI().getPath());
		assertEquals("/Sample Program.exe", GhidraURL.getProjectPathname(url));
		assertNull(url.getQuery());
		assertEquals(expected, GhidraURL.toURL(expected).toExternalForm());
		assertEquals(expected,
			GhidraURL.toURL(expected.replace("%20", " ")).toExternalForm());

		DefaultGhidraProtocolConnector connector = new DefaultGhidraProtocolConnector(url);
		assertEquals("Repository", connector.getRepositoryName());
		assertEquals("/", connector.getFolderPath());
		assertEquals("Sample Program.exe", connector.getFolderItemName());
	}

	@Test
	public void testResolveSpacesInLocalPathAndQuery() throws Exception {
		String path = "/folder/Sample Program.exe";
		for (String location : new String[] { "/my projects", "C:/my projects",
			"//server/my share" }) {
			ProjectLocator locator = new ProjectLocator(location, "My Project");
			URL base = locator.getURL();
			URL url = GhidraURL.resolve(base, path, null);
			String expected = base.toExternalForm() + "?/folder/Sample%20Program.exe";
			assertEquals(expected, url.toExternalForm());
			assertFalse(url.getPath().contains(" "));
			assertTrue(url.getPath().contains("%20"));
			assertTrue(url.toURI().getPath().endsWith("/My Project"));
			assertEquals("/folder/Sample%20Program.exe", url.getQuery());
			assertEquals(path, url.toURI().getQuery());
			assertEquals(path, GhidraURL.getProjectPathname(url));
			assertEquals(expected, GhidraURL.makeURL(locator, path, null).toExternalForm());
			assertEquals(expected, GhidraURL.toURL(expected).toExternalForm());
			assertEquals(expected,
				GhidraURL.toURL(expected.replace("%20", " ")).toExternalForm());

			DefaultLocalGhidraProtocolConnector connector =
				new DefaultLocalGhidraProtocolConnector(url);
			assertEquals(locator, connector.getLocalProjectLocator());
			assertEquals("/folder", connector.getFolderPath());
			assertEquals("Sample Program.exe", connector.getFolderItemName());
		}
	}

	@Test
	public void testResolveServerEncodedNames() throws Exception {
		String[] names = { "plain", "with space", "with[brackets]", "plus+name",
			"symbols.-=@_()~", "東京", "\uD801\uDC00" };
		for (String repository : names) {
			URL base = GhidraURL.makeURL("localhost", 123, repository, "/old", "old ref");
			for (String name : names) {
				for (String suffix : new String[] { "", "/" }) {
					String path = "/" + name + "/child" + suffix;
					URL resolved = GhidraURL.resolve(base, path, "new ref");
					URL expected = GhidraURL.makeURL("localhost", 123, repository, path,
						"new ref");
					assertEquals(expected.toExternalForm(), resolved.toExternalForm());
					assertEquals(repository, GhidraURL.getRepositoryName(resolved));
					assertEquals(path, GhidraURL.getProjectPathname(resolved));
					assertEquals("new ref", GhidraURL.getDecodedReference(resolved));
					assertNull(resolved.getQuery());
				}
			}
		}
	}

	@Test
	public void testResolveServerEncodedReferences() throws Exception {
		URL base = GhidraURL.makeURL("localhost", 123, "Repo", "/old", "old ref");
		String[] refs = { null, "", "ref with spaces", "literal%20escape", "a+b",
			"ref#?[]%&/\\", "東京" };
		for (String ref : refs) {
			URL resolved = GhidraURL.resolve(base, "/folder/file", ref);
			URL expected = GhidraURL.makeURL("localhost", 123, "Repo", "/folder/file", ref);
			assertEquals(expected.toExternalForm(), resolved.toExternalForm());
			assertEquals(ref, GhidraURL.getDecodedReference(resolved));
			assertEquals("/folder/file", GhidraURL.getProjectPathname(resolved));
		}
	}

	@Test
	public void testServerProjectAndFolderURLsWithEncodedNames() throws Exception {
		String repository = "Repo [a]+";
		String path = "/folder [b]+/file";
		String ref = "ref # %20 +";
		URL fileURL = GhidraURL.makeURL("localhost", 123, repository, path, ref);
		URL rootURL = GhidraURL.makeURL("localhost", 123, repository);
		assertEquals(rootURL.toExternalForm(), GhidraURL.getProjectURL(fileURL).toExternalForm());
		assertEquals(rootURL.toExternalForm(), GhidraURL.resolve(fileURL, null, null).toExternalForm());
		assertEquals(rootURL.toExternalForm(), GhidraURL.resolve(fileURL, "", null).toExternalForm());
		assertEquals(GhidraURL.makeURL("localhost", 123, repository, "/").toExternalForm(),
			GhidraURL.resolve(fileURL, "/", null).toExternalForm());

		URL folderURL = GhidraURL.getFolderURL(fileURL);
		assertEquals(GhidraURL.makeURL("localhost", 123, repository, path + "/", ref)
				.toExternalForm(), folderURL.toExternalForm());
		assertEquals(path + "/", GhidraURL.getProjectPathname(folderURL));
		assertEquals(ref, GhidraURL.getDecodedReference(folderURL));
		assertEquals(folderURL.toExternalForm(), GhidraURL.getFolderURL(folderURL).toExternalForm());
	}

	@Test
	public void testResolveExtensionEncodedNamesAndReferences() throws Exception {
		// Install a parsing-only extension handler; no network connection is needed.
		Field handlers = Handler.class.getDeclaredField("protocolHandlers");
		handlers.setAccessible(true);
		Object originalHandlers = handlers.get(null);
		GhidraProtocolHandler handler = new GhidraProtocolHandler() {
			@Override
			public boolean isExtensionSupported(String protocol) {
				return "https".equals(protocol);
			}

			@Override
			public GhidraProtocolConnector getConnector(URL url) {
				throw new UnsupportedOperationException("Parsing only");
			}
		};
		try {
			handlers.set(null, List.of(handler));
			String repository = "Repo [a]+";
			URI inner = new URI("https", null, "localhost", 123, "/" + repository + "/old",
				null, null);
			URL base = new URI(GhidraURL.PROTOCOL, inner.toString(), "old ref").toURL();
			for (String path : new String[] { null, "/", "/folder [b]+/東京",
				"/folder [b]+/東京/" }) {
				for (String ref : new String[] { null, "", "ref #?[]%20+ /\\" }) {
					String fullPath = "/" + repository + (path == null ? "" : path);
					URI expectedInner = new URI("https", null, "localhost", 123, fullPath,
						null, null);
					URL expected = new URI(GhidraURL.PROTOCOL, expectedInner.toString(), ref)
							.toURL();
					URL resolved = GhidraURL.resolve(base, path, ref);
					assertEquals(expected.toExternalForm(), resolved.toExternalForm());
					assertEquals(repository, GhidraURL.getRepositoryName(resolved));
					assertEquals(path == null ? "/" : path, GhidraURL.getProjectPathname(resolved));
					assertEquals(ref, GhidraURL.getDecodedReference(resolved));
				}
			}
		}
		finally {
			handlers.set(null, originalHandlers);
		}
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
		return new URI(GhidraURL.PROTOCOL, null, host, port, repoAndPath, null, ref).toURL();
	}
}
