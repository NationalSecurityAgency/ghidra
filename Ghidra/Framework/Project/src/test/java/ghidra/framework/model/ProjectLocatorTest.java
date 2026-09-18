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
package ghidra.framework.model;

import static org.junit.Assert.*;

import java.io.File;
import java.net.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.Application;
import ghidra.framework.OperatingSystem;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.protocol.ghidra.Handler;
import ghidra.util.NamingUtilities;

public class ProjectLocatorTest extends AbstractGenericTest {

	@Before
	public void setUp() {
		Handler.registerHandler();
	}

	//
	// Behavior of test differs when run on Windows vs Linux/Mac
	//

	private URL toGhidraLocalURL(String path) throws MalformedURLException, URISyntaxException {
		return new URI(GhidraURL.PROTOCOL, null, path, null).toURL();
	}

	@Test
	public void testPaths() throws Exception {

		ProjectLocator pl = new ProjectLocator("c:\\", "bob");
		assertEquals(toGhidraLocalURL("/c:/bob"), pl.getURL());
		assertEquals("/c:/", pl.getLocation());
		assertEquals(new File("/c:/bob.rep"), pl.getProjectDir());
		assertEquals(new File("/c:/bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());
		assertTrue(pl.isWindowsOnlyLocation());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			assertEquals("c:\\bob.rep", pl.getProjectDir().getAbsolutePath());
			assertEquals("c:\\bob.gpr", pl.getMarkerFile().getAbsolutePath());
		}

		pl = new ProjectLocator("/c:/", "bob");
		assertEquals(toGhidraLocalURL("/c:/bob"), pl.getURL());
		assertEquals("/c:/", pl.getLocation());
		assertEquals(new File("/c:/bob.rep"), pl.getProjectDir());
		assertEquals(new File("/c:/bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());
		assertTrue(pl.isWindowsOnlyLocation());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			assertEquals("c:\\bob.rep", pl.getProjectDir().getAbsolutePath());
			assertEquals("c:\\bob.gpr", pl.getMarkerFile().getAbsolutePath());
		}

		pl = new ProjectLocator("c:", "bob");
		assertEquals(toGhidraLocalURL("/c:/bob"), pl.getURL());
		assertEquals("/c:/", pl.getLocation());
		assertEquals(new File("/c:/bob.rep"), pl.getProjectDir());
		assertEquals(new File("/c:/bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());
		assertTrue(pl.isWindowsOnlyLocation());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			assertEquals("c:\\bob.rep", pl.getProjectDir().getAbsolutePath());
			assertEquals("c:\\bob.gpr", pl.getMarkerFile().getAbsolutePath());
		}

		pl = new ProjectLocator("c:\\a", "bob");
		assertEquals(toGhidraLocalURL("/c:/a/bob"), pl.getURL());
		assertEquals("/c:/a/", pl.getLocation());
		assertEquals(new File("/c:/a/bob.rep"), pl.getProjectDir());
		assertEquals(new File("/c:/a/bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());
		assertTrue(pl.isWindowsOnlyLocation());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			assertEquals("c:\\a\\bob.rep", pl.getProjectDir().getAbsolutePath());
			assertEquals("c:\\a\\bob.gpr", pl.getMarkerFile().getAbsolutePath());
		}

		pl = new ProjectLocator("c:\\a\\", "bob");
		assertEquals(toGhidraLocalURL("/c:/a/bob"), pl.getURL());
		assertEquals("/c:/a/", pl.getLocation());
		assertEquals(new File("/c:/a/bob.rep"), pl.getProjectDir());
		assertEquals(new File("/c:/a/bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());
		assertTrue(pl.isWindowsOnlyLocation());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			assertEquals("c:\\a\\bob.rep", pl.getProjectDir().getAbsolutePath());
			assertEquals("c:\\a\\bob.gpr", pl.getMarkerFile().getAbsolutePath());
		}

		// UNC path - sensitive to execution environment, requires Windows for proper use
		pl = new ProjectLocator("\\\\myserver\\myshare\\a", "bob");
		assertEquals(toGhidraLocalURL("////myserver/myshare/a/bob"), pl.getURL());
		assertEquals("//myserver/myshare/a/", pl.getLocation());
		assertEquals("bob", pl.getName());
		assertTrue(pl.isWindowsOnlyLocation());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			assertEquals("\\\\myserver\\myshare\\a\\bob.rep", pl.getProjectDir().getAbsolutePath());
			assertEquals("\\\\myserver\\myshare\\a\\bob.gpr", pl.getMarkerFile().getAbsolutePath());
		}
		else {
			// UNC path use not properly supported on non-windows platforms
			assertEquals(new File("/myserver/myshare/a/bob.rep"), pl.getProjectDir());
			assertEquals(new File("/myserver/myshare/a/bob.gpr"), pl.getMarkerFile());
		}

		pl = new ProjectLocator("\\", "bob");
		assertEquals(toGhidraLocalURL("/bob"), pl.getURL());
		assertEquals("/", pl.getLocation());
		assertEquals(new File("/bob.rep"), pl.getProjectDir());
		assertEquals(new File("/bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());
		assertFalse(pl.isWindowsOnlyLocation());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			// NOTE: Sensitive to default drive (test assumes C: )
			assertEquals("C:\\bob.rep", pl.getProjectDir().getAbsolutePath());
			assertEquals("C:\\bob.gpr", pl.getMarkerFile().getAbsolutePath());
		}

		pl = new ProjectLocator("\\a\\", "bob");
		assertEquals(toGhidraLocalURL("/a/bob"), pl.getURL());
		assertEquals("/a/", pl.getLocation());
		assertEquals(new File("/a/bob.rep"), pl.getProjectDir());
		assertEquals(new File("/a/bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());
		assertFalse(pl.isWindowsOnlyLocation());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			// NOTE: Sensitive to default drive (test assumes C: )
			assertEquals("C:\\a\\bob.rep", pl.getProjectDir().getAbsolutePath());
			assertEquals("C:\\a\\bob.gpr", pl.getMarkerFile().getAbsolutePath());
		}
	}

	@Test
	public void testSpecialCharsInPath() throws Exception {

		StringBuilder specialChars = new StringBuilder();
		for (Character c : NamingUtilities.VALID_NAME_CHARSET) {
			specialChars.append(c);
		}

		String dirName = "bill" + specialChars;
		String projName = "bob" + specialChars;

		ProjectLocator pl = new ProjectLocator("c:\\" + dirName, projName);
		assertEquals(toGhidraLocalURL("/c:/" + dirName + "/" + projName), pl.getURL());
		assertEquals("/c:/" + dirName + "/", pl.getLocation());
		assertEquals(new File("/c:/" + dirName + "/" + projName + ".rep"), pl.getProjectDir());
		assertEquals(new File("/c:/" + dirName + "/" + projName + ".gpr"), pl.getMarkerFile());
		assertEquals(projName, pl.getName());
		assertTrue(pl.isWindowsOnlyLocation());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			assertEquals("c:\\" + dirName + "\\" + projName + ".rep",
				pl.getProjectDir().getAbsolutePath());
			assertEquals("c:\\" + dirName + "\\" + projName + ".gpr",
				pl.getMarkerFile().getAbsolutePath());
		}

		pl = new ProjectLocator("/c:/" + dirName, projName);
		assertEquals(toGhidraLocalURL("/c:/" + dirName + "/" + projName), pl.getURL());
		assertEquals("/c:/" + dirName + "/", pl.getLocation());
		assertEquals(new File("/c:/" + dirName + "/" + projName + ".rep"), pl.getProjectDir());
		assertEquals(new File("/c:/" + dirName + "/" + projName + ".gpr"), pl.getMarkerFile());
		assertEquals(projName, pl.getName());
		assertTrue(pl.isWindowsOnlyLocation());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			assertEquals("c:\\" + dirName + "\\" + projName + ".rep",
				pl.getProjectDir().getAbsolutePath());
			assertEquals("c:\\" + dirName + "\\" + projName + ".gpr",
				pl.getMarkerFile().getAbsolutePath());
		}
	}

	@Test
	public void testTempPath() throws Exception {

		String tmpPath = Application.getUserTempDirectory().getAbsolutePath().replace("\\", "/");
		if (!tmpPath.startsWith("/")) {
			tmpPath = "/" + tmpPath;
		}
		if (!tmpPath.endsWith("/")) {
			tmpPath += "/";
		}

		ProjectLocator pl = new ProjectLocator("", "bob");
		assertEquals(tmpPath, pl.getLocation());
		assertEquals(toGhidraLocalURL(tmpPath + "bob"), pl.getURL());
		assertEquals(new File(pl.getLocation() + "bob.rep"), pl.getProjectDir());
		assertEquals(new File(pl.getLocation() + "bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());

		pl = new ProjectLocator(null, "bob");
		assertEquals(tmpPath, pl.getLocation());
		assertEquals(toGhidraLocalURL(tmpPath + "bob"), pl.getURL());
		assertEquals(new File(pl.getLocation() + "bob.rep"), pl.getProjectDir());
		assertEquals(new File(pl.getLocation() + "bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());
	}

	@Test
	public void testBadPaths() {

		// relative paths
		doTestBadPath("a/b", "bob");

		// bad paths chars
		doTestBadPath("/a?/b", "bob");
		doTestBadPath("/a#/b", "bob");
		doTestBadPath("/a/:b", "bob");
		doTestBadPath("/a;/b", "bob");
		doTestBadPath("/a&/b", "bob");

		// bad name chars
		doTestBadPath("/a/b", "b?ob");
		doTestBadPath("/a/b", "b#ob");
		doTestBadPath("/a/b", "b:ob");
		doTestBadPath("/a/b", "b;ob");
		doTestBadPath("/a/b", "b?ob");
		doTestBadPath("/a/b", "b&ob");
		doTestBadPath("/a/b", "b/ob");
		doTestBadPath("/a/b", "b\\ob");

	}

	private void doTestBadPath(String path, String name) {
		try {
			new ProjectLocator(path, name);
			fail("expected absolute path error");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}
}
