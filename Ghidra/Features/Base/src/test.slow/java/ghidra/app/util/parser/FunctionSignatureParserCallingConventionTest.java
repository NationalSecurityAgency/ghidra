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
package ghidra.app.util.parser;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ToyProgramBuilder;

public class FunctionSignatureParserCallingConventionTest
		extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private FunctionSignatureParser parser;

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ToyProgramBuilder("test", false);
		program = builder.getProgram();
		parser = new FunctionSignatureParser(program.getDataTypeManager(), null);
	}

	@Test
	public void testParseCdeclPointerSignature() throws Exception {
		FunctionDefinitionDataType function =
			parser.parse(null, "void * __cdecl test(void * arg0)");

		assertEquals("test", function.getName());
		assertEquals("__cdecl", function.getCallingConventionName());
		assertEquals("void * __cdecl test(void * arg0)", function.getPrototypeString(true));
	}

	@Test
	public void testParseGenericCallingConventions() throws Exception {
		List<GenericCallingConvention> conventions = List.of(GenericCallingConvention.cdecl,
			GenericCallingConvention.stdcall, GenericCallingConvention.fastcall,
			GenericCallingConvention.thiscall, GenericCallingConvention.vectorcall);

		for (GenericCallingConvention convention : conventions) {
			String declarationName = convention.getDeclarationName();
			FunctionDefinitionDataType function =
				parser.parse(null, "int " + declarationName + " test(int arg0)");

			assertEquals(declarationName, function.getCallingConventionName());
			assertEquals("int " + declarationName + " test(int arg0)",
				function.getPrototypeString(true));
		}
	}

	@Test
	public void testParseWithoutCallingConvention() throws Exception {
		FunctionDefinitionDataType function = parser.parse(null, "int test(int arg0)");

		assertEquals("int test(int arg0)", function.getPrototypeString());
	}
}
