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
import java.net.MalformedURLException;
import java.net.URL;

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
		URL ghidraUrl = GhidraURL.makeURL(loc);
		URL url = new URL("ghidra:/C:/junk/Test");
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("C:\\junk\\", "Test");
		ghidraUrl = GhidraURL.makeURL(loc);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/C:/junk", "Test");
		ghidraUrl = GhidraURL.makeURL(loc);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/C:/junk/", "Test");
		ghidraUrl = GhidraURL.makeURL(loc);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/a/b", "Test");
		ghidraUrl = GhidraURL.makeURL(loc);
		url = new URL("ghidra:/a/b/Test");
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/a/b/", "Test");
		ghidraUrl = GhidraURL.makeURL(loc);
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		try {
			loc = new ProjectLocator("a/b", "Test");
			fail("relative path shold not be permitted");
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
		URL url = new URL("ghidra:/C:/junk/Test");
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
		url = new URL("ghidra:/a/b/Test");
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		loc = new ProjectLocator("/a/b/", "Test");
		ghidraUrl = GhidraURL.makeURL("/a/b/", "Test");
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		try {
			ghidraUrl = GhidraURL.makeURL("a/b/", "Test");
			fail("relative path shold not be permitted");
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
		URL url = new URL("ghidra:/C:/junk/Test?/a#ref");
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL(loc, "/a/", "ref");
		url = new URL("ghidra:/C:/junk/Test?/a/#ref");
		assertEquals(url, ghidraUrl);

		try {
			ghidraUrl = GhidraURL.makeURL(loc, "a/b", "ref");
			fail("relative path shold not be permitted");
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
		URL url = new URL("ghidra:/C:/junk/Test?/a#ref");
		assertEquals(url, ghidraUrl);
		assertEquals(loc, GhidraURL.getProjectStorageLocator(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a/", "ref");
		url = new URL("ghidra:/C:/junk/Test?/a/#ref");
		assertEquals(url, ghidraUrl);

		try {
			ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "a/b", "ref");
			fail("relative path shold not be permitted");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	//	makeURL(String, int, String)
	@Test
	public void testMakeServerRepoURL() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test");
		URL url = new URL("ghidra", "localhost", 123, "/Test");
		assertEquals(url, ghidraUrl);
	}

	//	makeURL(String, int, String, String)
	@Test
	public void testMakeServerRepoFileURL() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/");
		URL url = new URL("ghidra", "localhost", 123, "/Test/foo/");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo");
		url = new URL("ghidra", "localhost", 123, "/Test/foo");
		assertEquals(url, ghidraUrl);

	}

	//	makeURL(String, int, String, String, String, String)
	@Test
	public void testMakeServerRepoFileURL2() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo", null, null);
		URL url = new URL("ghidra", "localhost", 123, "/Test/foo/");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/", null, null);
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo", "bar", "ref");
		url = new URL("ghidra", "localhost", 123, "/Test/foo/bar#ref");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/", "bar", "ref");
		assertEquals(url, ghidraUrl);
	}

//	makeURL(String, int, String, String)
	@Test
	public void testMakeServerRepoFileURL3() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo");
		URL url = new URL("ghidra", "localhost", 123, "/Test/foo");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/");
		url = new URL("ghidra", "localhost", 123, "/Test/foo/");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/bar", "ref");
		url = new URL("ghidra", "localhost", 123, "/Test/foo/bar#ref");
		assertEquals(url, ghidraUrl);

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/bar");
		url = new URL("ghidra", "localhost", 123, "/Test/foo/bar");
		assertEquals(url, ghidraUrl);
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

	//	isLocalProjectURL(URL)
	@Test
	public void testIsLocalProjectURL() throws Exception {
		URL ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test");
		assertTrue(GhidraURL.isLocalProjectURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a", "ref");
		assertTrue(GhidraURL.isLocalProjectURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("/x/y", "Test", "/a", "ref");
		assertTrue(GhidraURL.isLocalProjectURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test");
		assertFalse(GhidraURL.isLocalProjectURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/", "bar", "ref");
		assertFalse(GhidraURL.isLocalProjectURL(ghidraUrl));
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

		ghidraUrl = GhidraURL.makeURL("/x/y", "Test", "/a", "ref");
		assertNull(GhidraURL.getRepositoryName(ghidraUrl));
		assertFalse(GhidraURL.isServerRepositoryURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test");
		assertEquals("Test", GhidraURL.getRepositoryName(ghidraUrl));
		assertTrue(GhidraURL.isServerRepositoryURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/", "bar", "ref");
		assertEquals("Test", GhidraURL.getRepositoryName(ghidraUrl));
		assertTrue(GhidraURL.isServerRepositoryURL(ghidraUrl));

		ghidraUrl = new URL("ghidra", "localhost", 123, "");
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

		ghidraUrl = GhidraURL.makeURL("/x/y", "Test", "/a", "ref");
		assertFalse(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test");
		assertTrue(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/", "bar", "ref");
		assertTrue(GhidraURL.isServerURL(ghidraUrl));

		ghidraUrl = new URL("ghidra", "localhost", 123, "");
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

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a/", "ref");
		assertEquals(ghidraUrl, GhidraURL.toURL("ghidra:/C:/junk/Test?/a/#ref"));
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));

		ghidraUrl = GhidraURL.makeURL("/x/y", "Test", "/a/", "ref");
		assertEquals(ghidraUrl, GhidraURL.toURL("ghidra:/x/y/Test?/a/#ref"));
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo", "bar", "ref");
		assertEquals(ghidraUrl, GhidraURL.toURL(ghidraUrl.toString()));
		assertEquals(ghidraUrl, GhidraURL.toURL(GhidraURL.getDisplayString(ghidraUrl)));

	}

	@Test
	public void testGetProjectURL() throws Exception {

		URL ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test");
		assertEquals(new URL("ghidra:/C:/junk/Test"), GhidraURL.getProjectURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("C:\\junk", "Test", "/a", "ref");
		assertEquals(new URL("ghidra:/C:/junk/Test"), GhidraURL.getProjectURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("/x/y", "Test", "/a", "ref");
		assertEquals(new URL("ghidra:/x/y/Test"), GhidraURL.getProjectURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test");
		assertEquals(new URL("ghidra://localhost:123/Test"), GhidraURL.getProjectURL(ghidraUrl));

		ghidraUrl = GhidraURL.makeURL("localhost", 123, "Test", "/foo/", "bar", "ref");
		assertEquals(new URL("ghidra://localhost:123/Test"), GhidraURL.getProjectURL(ghidraUrl));

		ghidraUrl = new URL("ghidra", "localhost", 123, "");
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
		}
		finally {
			transientProjectManager.dispose();
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
}
