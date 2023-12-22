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
import java.net.MalformedURLException;
import java.net.URL;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.OperatingSystem;
import ghidra.framework.protocol.ghidra.Handler;

public class ProjectLocatorTest extends AbstractGenericTest {

	@Before
	public void setUp() {
		Handler.registerHandler();
	}

	//
	// Behavior of test differs when run on Windows vs Linux/Mac
	//

	@Test
	public void testPaths() throws MalformedURLException {

		ProjectLocator pl = new ProjectLocator("c:\\", "bob");
		assertEquals(new URL("ghidra:/c:/bob"), pl.getURL());
		assertEquals("/c:/", pl.getLocation());
		assertEquals(new File("/c:/bob.rep"), pl.getProjectDir());
		assertEquals(new File("/c:/bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			assertEquals("c:/bob.rep", pl.getProjectDir().getAbsolutePath());
			assertEquals("c:/bob.gpr", pl.getMarkerFile().getAbsolutePath());
		}

		pl = new ProjectLocator("/c:/", "bob");
		assertEquals(new URL("ghidra:/c:/bob"), pl.getURL());
		assertEquals("/c:/", pl.getLocation());
		assertEquals(new File("/c:/bob.rep"), pl.getProjectDir());
		assertEquals(new File("/c:/bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			assertEquals("c:/bob.rep", pl.getProjectDir().getAbsolutePath());
			assertEquals("c:/bob.gpr", pl.getMarkerFile().getAbsolutePath());
		}

		pl = new ProjectLocator("c:\\a", "bob");
		assertEquals(new URL("ghidra:/c:/a/bob"), pl.getURL());
		assertEquals("/c:/a/", pl.getLocation());
		assertEquals(new File("/c:/a/bob.rep"), pl.getProjectDir());
		assertEquals(new File("/c:/a/bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			assertEquals("c:/a/bob.rep", pl.getProjectDir().getAbsolutePath());
			assertEquals("c:/a/bob.gpr", pl.getMarkerFile().getAbsolutePath());
		}

		pl = new ProjectLocator("c:\\a\\", "bob");
		assertEquals(new URL("ghidra:/c:/a/bob"), pl.getURL());
		assertEquals("/c:/a/", pl.getLocation());
		assertEquals(new File("/c:/a/bob.rep"), pl.getProjectDir());
		assertEquals(new File("/c:/a/bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			assertEquals("c:/a/bob.rep", pl.getProjectDir().getAbsolutePath());
			assertEquals("c:/a/bob.gpr", pl.getMarkerFile().getAbsolutePath());
		}

		pl = new ProjectLocator("\\", "bob");
		assertEquals(new URL("ghidra:/bob"), pl.getURL());
		assertEquals("/", pl.getLocation());
		assertEquals(new File("/bob.rep"), pl.getProjectDir());
		assertEquals(new File("/bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			// NOTE: Sensitive to default drive for process
			assertEquals("c:/bob.rep", pl.getProjectDir().getAbsolutePath());
			assertEquals("c:/bob.gpr", pl.getMarkerFile().getAbsolutePath());
		}

		pl = new ProjectLocator("\\a\\", "bob");
		assertEquals(new URL("ghidra:/a/bob"), pl.getURL());
		assertEquals("/a/", pl.getLocation());
		assertEquals(new File("/a/bob.rep"), pl.getProjectDir());
		assertEquals(new File("/a/bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());

		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			// NOTE: Sensitive to default drive for process
			assertEquals("c:/a/bob.rep", pl.getProjectDir().getAbsolutePath());
			assertEquals("c:/a/bob.gpr", pl.getMarkerFile().getAbsolutePath());
		}
	}

	@Test
	public void testTempPath() throws MalformedURLException {

		String tmpPath = System.getProperty("java.io.tmpdir").replace("\\", "/");
		if (!tmpPath.startsWith("/")) {
			tmpPath = "/" + tmpPath;
		}
		if (!tmpPath.endsWith("/")) {
			tmpPath += "/";
		}

		ProjectLocator pl = new ProjectLocator("", "bob");
		assertEquals(tmpPath, pl.getLocation());
		assertEquals(new URL("ghidra:" + tmpPath + "bob"), pl.getURL());
		assertEquals(new File(pl.getLocation() + "bob.rep"), pl.getProjectDir());
		assertEquals(new File(pl.getLocation() + "bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());

		pl = new ProjectLocator(null, "bob");
		assertEquals(tmpPath, pl.getLocation());
		assertEquals(new URL("ghidra:" + tmpPath + "bob"), pl.getURL());
		assertEquals(new File(pl.getLocation() + "bob.rep"), pl.getProjectDir());
		assertEquals(new File(pl.getLocation() + "bob.gpr"), pl.getMarkerFile());
		assertEquals("bob", pl.getName());
	}

	@Test
	public void testBadPaths() {

		// relative paths
		doTestBadPath("c:", "bob");
		doTestBadPath("/c:", "bob");
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
