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

public class DefaultLocalGhidraProtocolConnectorParseTest extends AbstractGenericTest {

	static {
		Handler.registerHandler();
	}

	@Test
	public void testParseURL() throws Exception {

		DefaultLocalGhidraProtocolConnector pp =
			new DefaultLocalGhidraProtocolConnector(new URL("ghidra:/C:/x/y/proj"));
		assertNull(pp.getRepositoryName());
		assertEquals("/", pp.getFolderPath());
		assertNull(pp.getFolderItemName());
		assertEquals("/", getInstanceField("itemPath", pp));

		pp = new DefaultLocalGhidraProtocolConnector(new URL("ghidra:/x/y/proj"));
		assertNull(pp.getRepositoryName());
		assertEquals("/", pp.getFolderPath());
		assertNull(pp.getFolderItemName());
		assertEquals("/", getInstanceField("itemPath", pp));

		pp = new DefaultLocalGhidraProtocolConnector(new URL("ghidra:/x/y/proj?/"));
		assertNull(pp.getRepositoryName());
		assertEquals("/", pp.getFolderPath());
		assertNull(pp.getFolderItemName());
		assertEquals("/", getInstanceField("itemPath", pp));

		pp = new DefaultLocalGhidraProtocolConnector(new URL("ghidra:/x/y/proj?/a"));
		assertNull(pp.getRepositoryName());
		assertEquals("/", pp.getFolderPath());
		assertEquals("a", pp.getFolderItemName());
		assertEquals("/a", getInstanceField("itemPath", pp));

		pp = new DefaultLocalGhidraProtocolConnector(new URL("ghidra:/x/y/proj?/a/b#ref"));
		assertNull(pp.getRepositoryName());
		assertEquals("/a", pp.getFolderPath());
		assertEquals("b", pp.getFolderItemName());
		assertEquals("/a/b", getInstanceField("itemPath", pp));

		try {
			pp =
				new DefaultLocalGhidraProtocolConnector(new URL("ghidra:/x/y/proj?//"));
			fail();
		}
		catch (MalformedURLException e) {
			// expected
		}

	}
}
