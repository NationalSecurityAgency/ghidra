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
package ghidra.features.bsim.query.client;

import static org.junit.Assert.*;

import java.net.URI;
import java.net.URL;

import org.junit.Test;

import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class BSimServerInfoTest extends AbstractGhidraHeadlessIntegrationTest {

	@Test
	public void testBadFilename1() {
		Exception e = assertThrows(IllegalArgumentException.class, () -> {
			BSimServerInfo h2Info = new BSimServerInfo("C:\\dir\\test\"test");
			assertNull(h2Info);
		});
		assertTrue(e.getMessage().contains("characters"));
	}

	@Test
	public void testBadFilename2() {
		Exception e = assertThrows(IllegalArgumentException.class, () -> {
			BSimServerInfo h2Info = new BSimServerInfo(DBType.file, "user", 1, "/test'test");
			assertNull(h2Info);
		});
		assertTrue(e.getMessage().contains("characters"));
	}

	@Test
	public void testBadFilename3() {
		Exception e = assertThrows(IllegalArgumentException.class, () -> {
			URL url = new URI("file:/test;test").toURL();
			BSimServerInfo h2Info = new BSimServerInfo(url);
			assertNull(h2Info);
		});
		assertTrue(e.getMessage().contains("characters"));
	}

	@Test
	public void testBadDirectory1() {
		Exception e = assertThrows(IllegalArgumentException.class, () -> {
			BSimServerInfo h2Info = new BSimServerInfo("C:\\dir;1\\test");
			assertNull(h2Info);
		});
		assertTrue(e.getMessage().contains("characters"));
	}

	@Test
	public void testBadDirectory2() {
		Exception e = assertThrows(IllegalArgumentException.class, () -> {
			BSimServerInfo h2Info = new BSimServerInfo("C:\\dir'1\\test");
			assertNull(h2Info);
		});
		assertTrue(e.getMessage().contains("characters"));
	}

	@Test
	public void testBadDirectory3() {
		Exception e = assertThrows(IllegalArgumentException.class, () -> {
			BSimServerInfo h2Info = new BSimServerInfo("/dir1/dir\"/2/testdb");
			assertNull(h2Info);
		});
		assertTrue(e.getMessage().contains("characters"));
	}

	@Test
	public void testBadPathWindows() {
		Exception e = assertThrows(IllegalArgumentException.class, () -> {
			BSimServerInfo h2Info = new BSimServerInfo("C:\\directory\\");
			assertNull(h2Info);
		});
		assertTrue(e.getMessage().contains("Invalid absolute file path"));
	}

	@Test
	public void testBadPathLinux() {
		Exception e = assertThrows(IllegalArgumentException.class, () -> {
			BSimServerInfo h2Info = new BSimServerInfo("/dir1/dir2/");
			assertNull(h2Info);
		});
		assertTrue(e.getMessage().contains("Invalid absolute file path"));
	}

	@Test
	public void testBadPathLinux2() {
		Exception e = assertThrows(IllegalArgumentException.class, () -> {
			BSimServerInfo h2Info = new BSimServerInfo("dir1/dir2/dir3/file");
			assertNull(h2Info);
		});
		assertTrue(e.getMessage().contains("Invalid absolute file path"));
	}

	@Test
	public void testPaths() {
		BSimServerInfo h2Info = new BSimServerInfo("/dir1/dir2/dir3/file");
		assertEquals("/dir1/dir2/dir3/file.mv.db", h2Info.getDBName());
		h2Info = new BSimServerInfo("/dir1/dir2/dir3/file.mv.db");
		assertEquals("/dir1/dir2/dir3/file.mv.db", h2Info.getDBName());
		h2Info = new BSimServerInfo("C:\\dir1 2\\file3 4");
		assertEquals("C:/dir1 2/file3 4.mv.db", h2Info.getDBName());

	}

}
