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
package ghidra.program.database.map;

import static org.junit.Assert.assertNotNull;

import org.junit.After;
import org.junit.Before;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public abstract class AbstractAddressMapDBTestClass extends AbstractGhidraHeadedIntegrationTest {

	protected TestEnv env;
	protected Program program;
	protected AddressMap addrMap;

	/**
	 * Constructor for AddressMapTest.
	 * @param arg0
	 */
	public AbstractAddressMapDBTestClass() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		program = createTestProgram();
		MemoryMapDB memory = (MemoryMapDB) program.getMemory();
		addrMap = (AddressMap) getInstanceField("addrMap", memory);
	}

	@After
	public void tearDown() {
		if (program != null) {
			program.release(this);
		}
		addrMap = null;
		env.dispose();
	}

	protected Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * Create empty program - do not forget to release
	 * @param languageID
	 * @return program
	 * @throws Exception
	 */
	protected Program createProgram(LanguageID languageID) throws Exception {
		LanguageService service = getLanguageService();
		Language lang = service.getLanguage(languageID);
		return new ProgramDB("test", lang, lang.getDefaultCompilerSpec(), this);
	}

	protected Program createProgram(Processor processor) throws Exception {
		LanguageService service = getLanguageService();
		Language lang = service.getDefaultLanguage(processor);
		return new ProgramDB("test", lang, lang.getDefaultCompilerSpec(), this);
	}

	protected Program createProgram(Processor processor, int size) throws Exception {
		Language lang = getLanguage(processor, size);
		return new ProgramDB("test", lang, lang.getDefaultCompilerSpec(), this);
	}

	protected Language getLanguage(Processor processor, int size) {
		Language lang = null;
		try {
			LanguageService service = getLanguageService();
			lang = service.getDefaultLanguage(processor);
			if (size != lang.getLanguageDescription().getSize()) {
				lang = null;
				for (LanguageDescription def : service.getLanguageDescriptions(processor)) {
					if (def.getSize() == size) {
						lang = service.getLanguage(def.getLanguageID());
						break;
					}
				}
			}
		}
		catch (LanguageNotFoundException e) {
			// handled by assert below
		}
		assertNotNull("Language not found for processor " + processor + ", size=" + size, lang);
		return lang;
	}

	protected abstract Program createTestProgram() throws Exception;

}
