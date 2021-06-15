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
package pdb.symbolserver;

import static org.junit.Assert.*;

import java.util.List;

import java.io.File;
import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class SymbolServerInstanceCreatorRegistryTest extends AbstractGenericTest {

	private SymbolServerInstanceCreatorRegistry symbolServerInstanceCreatorRegistry =
		SymbolServerInstanceCreatorRegistry.getInstance();
	private SymbolServerInstanceCreatorContext symbolServerInstanceCreatorContext =
		symbolServerInstanceCreatorRegistry.getContext();
	private File temporaryDir;

	@Before
	public void setup() throws IOException {
		temporaryDir = createTempDirectory("localsymbolserver");
	}

	@Test
	public void testCreateLocalSymbolStore() {
		SymbolServer symbolServer = symbolServerInstanceCreatorRegistry
				.newSymbolServer(temporaryDir.getPath(), symbolServerInstanceCreatorContext);
		assertNotNull(symbolServer);
		assertTrue(symbolServer instanceof LocalSymbolStore);
	}

	@Test
	public void testCreateHttpSymbolServer() {
		SymbolServer symbolServer = symbolServerInstanceCreatorRegistry
				.newSymbolServer("http://localhost/blah", symbolServerInstanceCreatorContext);
		assertNotNull(symbolServer);
		assertTrue(symbolServer instanceof HttpSymbolServer);
	}

	@Test
	public void testCreateHttpsSymbolServer() {
		SymbolServer symbolServer = symbolServerInstanceCreatorRegistry
				.newSymbolServer("https://localhost/blah", symbolServerInstanceCreatorContext);
		assertNotNull(symbolServer);
		assertTrue(symbolServer instanceof HttpSymbolServer);
	}

	@Test
	public void testCreateSameDirSymbolStore() {
		SymbolServer symbolServer = symbolServerInstanceCreatorRegistry.newSymbolServer(".",
			symbolServerInstanceCreatorContext);
		assertNotNull(symbolServer);
		assertTrue(symbolServer instanceof SameDirSymbolStore);
	}

	@Test
	public void testCreateDisabledSymbolServer() {
		SymbolServer symbolServer = symbolServerInstanceCreatorRegistry
				.newSymbolServer("disabled://.", symbolServerInstanceCreatorContext);
		assertNotNull(symbolServer);
		assertTrue(symbolServer instanceof DisabledSymbolServer);
		assertTrue(
			((DisabledSymbolServer) symbolServer).getSymbolServer() instanceof SameDirSymbolStore);
	}

	@Test
	public void testBogusLocation() {
		SymbolServer symbolServer = symbolServerInstanceCreatorRegistry.newSymbolServer("blah://",
			symbolServerInstanceCreatorContext);
		assertNull(symbolServer);
	}

	@Test
	public void testPath() {
		List<SymbolServer> symbolServerResultList =
			symbolServerInstanceCreatorRegistry.createSymbolServersFromPathList(
				List.of(".", "http://localhost/blah"), symbolServerInstanceCreatorContext);
		assertEquals(2, symbolServerResultList.size());
		assertTrue(symbolServerResultList.get(0) instanceof SameDirSymbolStore);
		assertTrue(symbolServerResultList.get(1) instanceof HttpSymbolServer);
	}
}
