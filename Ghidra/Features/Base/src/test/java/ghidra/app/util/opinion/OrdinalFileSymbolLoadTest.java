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
package ghidra.app.util.opinion;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.Test;

import generic.jar.ResourceFile;
import resources.ResourceManager;

public class OrdinalFileSymbolLoadTest {

	protected static final String ORD_TEST_FILE = "ghidra/app/util/opinion/test.ord";

	@Test
	public void testORDFileParse() {

		File ordFile = ResourceManager.getResourceFile(ORD_TEST_FILE);
		assertNotNull(ordFile);

		ResourceFile ordResourceFile = new ResourceFile(ordFile);

		LibrarySymbolTable symTable = new LibrarySymbolTable("test", 32);
		symTable.applyOrdinalFile(ordResourceFile, true);

		LibraryExportedSymbol symbol = symTable.getSymbol(1);
		assertNotNull(symbol);
		assertEquals("SymbolName1", symbol.getName());
		assertEquals(-1, symbol.getPurge());
		assertEquals("test", symbol.getLibraryName());

		symbol = symTable.getSymbol(2);
		assertNotNull(symbol);
		assertEquals("SymbolName2", symbol.getName());
		assertEquals(-1, symbol.getPurge());
		assertEquals("test", symbol.getLibraryName());

		symbol = symTable.getSymbol(20);
		assertNotNull(symbol);
		assertEquals("SymbolName3", symbol.getName());
		assertEquals(-1, symbol.getPurge());
		assertEquals("test", symbol.getLibraryName());

		symbol = symTable.getSymbol(30);
		assertNotNull(symbol);
		assertEquals("SymbolName4", symbol.getName());
		assertEquals(-1, symbol.getPurge());
		assertEquals("test", symbol.getLibraryName());

		symbol = symTable.getSymbol(40);
		assertNotNull(symbol);
		assertEquals("SymbolName5", symbol.getName());
		assertEquals(-1, symbol.getPurge());
		assertEquals("test", symbol.getLibraryName());

		symbol = symTable.getSymbol(50);
		assertNull(symbol);

		symbol = symTable.getSymbol(60);
		assertNotNull(symbol);
		assertEquals("SymbolName6", symbol.getName());
		assertEquals(-1, symbol.getPurge());
		assertEquals("test", symbol.getLibraryName());

	}

}
