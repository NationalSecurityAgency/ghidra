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
package ghidra.program.model.listing;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.framework.Application;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;

public class VariableUtilitiesTest extends AbstractGenericTest {

	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		Language language = getLanguage("Toy:BE:64:default");
		CompilerSpec compilerSpec = language.getDefaultCompilerSpec();
		program = new ProgramDB("Test", language, compilerSpec, this);
	}

	private Language getLanguage(String languageName) throws Exception {
		ResourceFile ldefFile = Application.getModuleDataFile("Toy", "languages/toy.ldefs");
		if (ldefFile != null) {
			LanguageService languageService = DefaultLanguageService.getLanguageService(ldefFile);
			Language language = languageService.getLanguage(new LanguageID(languageName));
			return language;
		}
		throw new LanguageNotFoundException("Unsupported test language: " + languageName);
	}

	@Test
	public void testCheckDataType() throws Exception {

		DataType dt = new TypedefDataType("Foo", new PointerDataType()); // point size will be 8 in program
		assertEquals(4, dt.getLength());

		dt = VariableUtilities.checkDataType(dt, false, -1, program);
		assertEquals(8, dt.getLength());

		dt = new ArrayDataType(new PointerDataType(), 5, -1); // point size will be 8 in program
		assertEquals(20, dt.getLength());

		dt = VariableUtilities.checkDataType(dt, false, -1, program);
		assertEquals(40, dt.getLength());
	}
}
