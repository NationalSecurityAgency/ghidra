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
import java.net.URL;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class DefaultGhidraProtocolConnectorParseTest extends AbstractGenericTest {

	static {
		Handler.registerHandler();
	}

	@Test
	public void testParseURL() throws Exception {

		DefaultGhidraProtocolConnector pp =
			new DefaultGhidraProtocolConnector(new URL("ghidra://myhost"));

		try {
			pp = new DefaultGhidraProtocolConnector(new URL("ghidra://myhost//"));
			fail();
		}
		catch (MalformedURLException e) {
			// expected
		}

		pp = new DefaultGhidraProtocolConnector(new URL("ghidra://myhost/"));
		assertNull(pp.getRepositoryName());
		assertNull(pp.getFolderPath());
		assertNull(pp.getFolderItemName());
		assertNull(getInstanceField("itemPath", pp));

		pp = new DefaultGhidraProtocolConnector(new URL("ghidra://myhost/repo"));
		assertEquals("repo", pp.getRepositoryName());
		assertEquals("/", pp.getFolderPath());
		assertNull(pp.getFolderItemName());
		assertEquals("/", getInstanceField("itemPath", pp));

		try {
			pp = new DefaultGhidraProtocolConnector(new URL("ghidra://myhost/repo//"));
			fail();
		}
		catch (MalformedURLException e) {
			// expected
		}

		pp = new DefaultGhidraProtocolConnector(new URL("ghidra://myhost/repo/"));
		assertEquals("repo", pp.getRepositoryName());
		assertEquals("/", pp.getFolderPath());
		assertNull(pp.getFolderItemName());
		assertEquals("/", getInstanceField("itemPath", pp));

		pp = new DefaultGhidraProtocolConnector(new URL("ghidra://myhost/repo/a"));
		assertEquals("repo", pp.getRepositoryName());
		assertEquals("/", pp.getFolderPath());
		assertEquals("a", pp.getFolderItemName());
		assertEquals("/a", getInstanceField("itemPath", pp));

		try {
			pp = new DefaultGhidraProtocolConnector(new URL("ghidra://myhost/repo/a//"));
			fail();
		}
		catch (MalformedURLException e) {
			// expected
		}

		try {
			pp = new DefaultGhidraProtocolConnector(new URL("ghidra://myhost/repo/a///"));
			fail();
		}
		catch (MalformedURLException e) {
			// expected
		}

		pp = new DefaultGhidraProtocolConnector(new URL("ghidra://myhost/repo/a/"));
		assertEquals("repo", pp.getRepositoryName());
		assertEquals("/a", pp.getFolderPath());
		assertNull(pp.getFolderItemName());
		assertEquals("/a/", getInstanceField("itemPath", pp));

		pp = new DefaultGhidraProtocolConnector(new URL("ghidra://myhost/repo/a/b"));
		assertEquals("repo", pp.getRepositoryName());
		assertEquals("/a", pp.getFolderPath());
		assertEquals("b", pp.getFolderItemName());
		assertEquals("/a/b", getInstanceField("itemPath", pp));

		pp = new DefaultGhidraProtocolConnector(new URL("ghidra://myhost/repo/a/b/"));
		assertEquals("repo", pp.getRepositoryName());
		assertEquals("/a/b", pp.getFolderPath());
		assertNull(pp.getFolderItemName());
		assertEquals("/a/b/", getInstanceField("itemPath", pp));

		try {
			pp = new DefaultGhidraProtocolConnector(new URL("ghidra://myhost/repo/a/b//"));
			fail();
		}
		catch (MalformedURLException e) {
			// expected
		}

		pp = new DefaultGhidraProtocolConnector(new URL("ghidra://myhost/repo/a/b#junk"));
		assertEquals("repo", pp.getRepositoryName());
		assertEquals("/a", pp.getFolderPath());
		assertEquals("b", pp.getFolderItemName());
		assertEquals("/a/b", getInstanceField("itemPath", pp));
	}

}
