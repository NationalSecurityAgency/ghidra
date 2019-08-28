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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ToyProgramBuilder;

public class FunctionSignatureParserTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private FunctionSignatureParser parser;

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ToyProgramBuilder("test", false);
		program = builder.getProgram();
		parser = new FunctionSignatureParser(program, null);
	}

	@Test
	public void testSubstitute() {
		assertEquals("barxxxbar", parser.substitute("barfoobar", "foo", "xxx"));
		assertEquals("barxxx]bar", parser.substitute("bar[foo]bar", "[foo", "xxx"));
	}

	@Test
	public void testCleanUpSignatureTextWithFunkyReturnType() {
		FunctionSignature f = fun("abc(d", "Bob", "int", "a");

		String result = parser.cleanUpSignatureText("abc(d Bob(int a)", f);
		assertEquals("__REPLACE_DT_NAME__ Bob(int a)", result);

	}

	@Test
	public void testCleanUpSignatureTextWithFunkyFunctionName() {
		FunctionSignature f = fun("int", "<Bob,Joe>", "int", "a");

		String result = parser.cleanUpSignatureText("int <Bob,Joe>(int a)", f);
		assertEquals("int __REPLACE_NAME__(int a)", result);

	}

	@Test
	public void testCleanUpSignatureTextWithFunkyParamName() {
		FunctionSignature f = fun("int", "Bob", "int", "{,a>");

		String result = parser.cleanUpSignatureText("int Bob(int {,a>)", f);
		assertEquals("int Bob(int __REPLACE_NAME__0)", result);
	}

	@Test
	public void testCleanUpSignatureTextWithFunkyParamDatatype() {
		FunctionSignature f = fun("int", "Bob", "(aaa)", "a");

		String result = parser.cleanUpSignatureText("int Bob((aaa) a)", f);
		assertEquals("int Bob(__REPLACE_DT_NAME__0 a)", result);
	}

	@Test
	public void testExtractFunctionName() throws Exception {
		assertEquals("bob", parser.extractFunctionName("void bob(int a)"));
		assertEquals("bob", parser.extractFunctionName("void    bob    (int a)"));
	}

	@Test
	public void testExtractReturnTypeName() throws Exception {
		DataType voidDt = BuiltInDataTypeManager.getDataTypeManager().getDataType("/void");
		assertEquals(voidDt, parser.extractReturnType("void bob(int a)"));
		assertEquals(voidDt, parser.extractReturnType("void    bob    (int a)"));
	}

	@Test
	public void testParseSimple() throws ParseException {
		FunctionDefinitionDataType dt = parser.parse(null, "int Bob(int a, float b)");
		assertEquals("int Bob(int a, float b)", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testParseWithFunkyFunctionName() throws ParseException {
		FunctionSignature f = fun("int", "Bo<{}?>b", "int", "a", "float", "b");

		FunctionDefinitionDataType dt = parser.parse(f, "int Bo<{}?>b(int a, int b)");
		assertEquals("int Bo<{}?>b(int a, int b)", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testParseWithFunkyParamDataType() throws ParseException {
		FunctionSignature f = fun("int", "Bob", "int", "a", "Bo<{()", "b");

		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(float a, Bo<{() b)");
		assertEquals("int Bob(float a, Bo<{() b)", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testParseWithFunkyParamName() throws ParseException {
		FunctionSignature f = fun("int", "Bob", "int", "a()<>@", "int", "b");

		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(float a()<>@, int b)");
		assertEquals("int Bob(float a()<>@, int b)", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testParseWithFunkyReturnType() throws ParseException {
		FunctionSignature f = fun("abc(d", "Bob", "int", "a");

		FunctionDefinitionDataType dt = parser.parse(f, "abc(d Bob(int a, float b)");
		assertEquals("abc(d Bob(int a, float b)", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testParseWithMultiWordCtypes() throws ParseException {
		FunctionSignature f = fun("int", "Bob");

		FunctionDefinitionDataType dt =
			parser.parse(f, "signed char Bob(long long a, unsigned int b)");
		assertEquals("char Bob(longlong a, uint b)", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testSpacesNotAllowedInTypedFunctionName() {
		FunctionSignature f = fun("int", "Bob", "int", "a");

		FunctionDefinitionDataType dt;
		try {
			dt = parser.parse(f, "int bo b(int a, float b)");
			fail("parsed name with space");
		}
		catch (ParseException e) {
			assertTrue(e.getMessage().contains("Can't resolve"));
		}
	}

	@Test
	public void testVarArgs() throws ParseException {
		FunctionSignature f = fun("int", "Bob", "int", "a");

		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(int a, float b, ...)");
		assertTrue(dt.hasVarArgs());
		assertEquals("int Bob(int a, float b, ...)", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testNoArgs() throws ParseException {
		FunctionSignature f = fun("int", "Bob", "int", "a");

		FunctionDefinitionDataType dt = parser.parse(f, "int Bob()");
		assertEquals(0, dt.getArguments().length);
	}

	@Test
	public void testVoidArgs() throws ParseException {
		FunctionSignature f = fun("int", "Bob", "int", "a");

		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(void)");
		assertEquals(0, dt.getArguments().length);
	}

	@Test
	public void testNoParamNames() throws ParseException {
		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(int, float)");
		ParameterDefinition[] args = dt.getArguments();
		assertEquals(2, args.length);
		assertEquals("", args[0].getName());
		assertEquals("", args[1].getName());
	}

	@Test
	public void testMultiWordDataTypesWithNoParamNames() throws ParseException {
		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(unsigned int, float)");
		ParameterDefinition[] args = dt.getArguments();
		assertEquals(2, args.length);
		assertEquals("", args[0].getName());
		assertEquals("", args[1].getName());
	}

	@Test
	public void testBadReturnType() {
		FunctionSignature f = fun("int", "Bob");
		try {
			parser.parse(f, "xyz Bob(int, float)");
			fail("Expected parse error");
		}
		catch (ParseException e) {
			//expected
		}
	}

	@Test
	public void testUnsignedLong() throws ParseException {
		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(unsigned long bob, float)");
		assertEquals("int Bob(ulong bob, float )", dt.getRepresentation(null, null, 0));

	}

	@Test
	public void testPointerNoSpaceBeforeName() throws ParseException {
		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(char *bob, float)");
		assertEquals("int Bob(char * bob, float )", dt.getRepresentation(null, null, 0));
	}

	private DataType createDataType(String name) {
		if (name.equals("int")) {
			return new IntegerDataType();
		}
		return new StructureDataType(name, 2);
	}

	private FunctionSignature fun(String returnType, String name, String... args) {
		FunctionDefinitionDataType f = new FunctionDefinitionDataType(name);
		f.setReturnType(createDataType(returnType));
		ParameterDefinition[] params = new ParameterDefinition[args.length / 2];
		for (int i = 0; i < params.length; i++) {
			params[i] =
				new ParameterDefinitionImpl(args[i * 2 + 1], createDataType(args[i * 2]), null);
		}
		f.setArguments(params);
		return f;
	}

}
