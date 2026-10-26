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

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class DefaultLocalGhidraProtocolConnectorParseTest extends AbstractGenericTest {

	static {
		Handler.registerHandler();
	}

	@Test
	public void testParseURL() throws Exception {

		DefaultLocalGhidraProtocolConnector pp =
			new DefaultLocalGhidraProtocolConnector(
				new URI(GhidraURL.PROTOCOL, "/C:/x/y/proj", null).toURL());
		assertEquals("proj", pp.getRepositoryName());
		assertEquals("/", pp.getFolderPath());
		assertNull(pp.getFolderItemName());
		assertEquals("/", getInstanceField("itemPath", pp));

		pp = new DefaultLocalGhidraProtocolConnector(
			new URI(GhidraURL.PROTOCOL, "/x/y/proj", null).toURL());
		assertEquals("proj", pp.getRepositoryName());
		assertEquals("/", pp.getFolderPath());
		assertNull(pp.getFolderItemName());
		assertEquals("/", getInstanceField("itemPath", pp));

		pp = new DefaultLocalGhidraProtocolConnector(
			new URI(GhidraURL.PROTOCOL, "/x/y/proj?/", null).toURL());
		assertEquals("proj", pp.getRepositoryName());
		assertEquals("/", pp.getFolderPath());
		assertNull(pp.getFolderItemName());
		assertEquals("/", getInstanceField("itemPath", pp));

		pp = new DefaultLocalGhidraProtocolConnector(
			new URI(GhidraURL.PROTOCOL, "/x/y/proj?/a", null).toURL());
		assertEquals("proj", pp.getRepositoryName());
		assertEquals("/", pp.getFolderPath());
		assertEquals("a", pp.getFolderItemName());
		assertEquals("/a", getInstanceField("itemPath", pp));

		pp = new DefaultLocalGhidraProtocolConnector(
			new URI(GhidraURL.PROTOCOL, "/x/y/proj?/a/b", "ref").toURL());
		assertEquals("proj", pp.getRepositoryName());
		assertEquals("/a", pp.getFolderPath());
		assertEquals("b", pp.getFolderItemName());
		assertEquals("/a/b", getInstanceField("itemPath", pp));

		try {
			pp = new DefaultLocalGhidraProtocolConnector(
				new URI(GhidraURL.PROTOCOL, "/x/y/proj?//", null).toURL());
			fail();
		}
		catch (MalformedURLException e) {
			// expected
		}

	}

	@Test
	public void testParseUNCProjectFileURL() throws Exception {

		URL url = GhidraURL.makeURL("//server/share", "Project", "/folder/file", null);
		assertEquals("ghidra:////server/share/Project?/folder/file", url.toExternalForm());
		assertTrue(GhidraURL.isLocalURL(url));
		assertEquals("//server/share/", GhidraURL.getProjectStorageLocator(url).getLocation());
		assertEquals("Project", GhidraURL.getProjectStorageLocator(url).getName());
		assertEquals("/folder/file", GhidraURL.getProjectPathname(url));

		DefaultLocalGhidraProtocolConnector connector =
			new DefaultLocalGhidraProtocolConnector(url);
		assertEquals("Project", connector.getRepositoryName());
		assertEquals("//server/share/", connector.getLocalProjectLocator().getLocation());
		assertEquals("/folder", connector.getFolderPath());
		assertEquals("file", connector.getFolderItemName());
		assertEquals("/folder/file", getInstanceField("itemPath", connector));
	}

	@Test
	public void testParseUNCProjectRootAndFolderURLs() throws Exception {
		for (String location : new String[] { "//server/share", "\\\\server\\share" }) {
			for (String path : new String[] { null, "/", "/folder [a]+/東京/" }) {
				URL url = GhidraURL.makeURL(location, "Project [a]+", path, "ref");
				url = URI.create(url.toURI().toASCIIString()).toURL();
				DefaultLocalGhidraProtocolConnector connector =
					new DefaultLocalGhidraProtocolConnector(url);
				assertEquals("Project [a]+", connector.getRepositoryName());
				assertEquals("//server/share/", connector.getLocalProjectLocator().getLocation());
				assertEquals(GhidraURL.getProjectStorageLocator(url),
					connector.getLocalProjectLocator());
				String expectedPath = path == null ? "/" : path;
				assertEquals(expectedPath, getInstanceField("itemPath", connector));
				assertEquals(expectedPath.equals("/") ? "/"
						: expectedPath.substring(0, expectedPath.length() - 1),
					connector.getFolderPath());
				assertNull(connector.getFolderItemName());
			}
		}
	}

	@Test
	public void testParseEncodedFileNames() throws Exception {
		String[] names = { "with space", "with[brackets]", "plus+name", "東京", "\uD801\uDC00" };
		for (String folder : names) {
			for (String file : names) {
				String path = "/" + folder + "/" + file;
				URL url = GhidraURL.makeURL("/projects", "Project", path, "ref # %20 +");
				// Also exercise percent-encoded Unicode, as received in an external URL.
				url = URI.create(url.toURI().toASCIIString()).toURL();
				DefaultLocalGhidraProtocolConnector connector =
					new DefaultLocalGhidraProtocolConnector(url);
				assertEquals("/" + folder, connector.getFolderPath());
				assertEquals(file, connector.getFolderItemName());
				assertEquals(path, getInstanceField("itemPath", connector));
				assertEquals(GhidraURL.getProjectPathname(url),
					getInstanceField("itemPath", connector));
				assertEquals("Project", connector.getRepositoryName());
			}
		}
	}

	@Test
	public void testParseEncodedFolderPath() throws Exception {
		String folderPath = "/folder with spaces/東京 [a]+";
		URL url = GhidraURL.makeURL("/projects", "Project", folderPath + "/", "ref");
		url = URI.create(url.toURI().toASCIIString()).toURL();
		DefaultLocalGhidraProtocolConnector connector =
			new DefaultLocalGhidraProtocolConnector(url);
		assertEquals(folderPath, connector.getFolderPath());
		assertNull(connector.getFolderItemName());
		assertEquals(folderPath + "/", getInstanceField("itemPath", connector));
	}

	@Test
	public void testParseEncodedFileAtRoot() throws Exception {
		String name = "file + [a]";
		URL url = GhidraURL.makeURL("/projects", "Project", "/" + name, null);
		DefaultLocalGhidraProtocolConnector connector =
			new DefaultLocalGhidraProtocolConnector(url);
		assertEquals("/", connector.getFolderPath());
		assertEquals(name, connector.getFolderItemName());
		assertEquals("/" + name, getInstanceField("itemPath", connector));
	}
}
