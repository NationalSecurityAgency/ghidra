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

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.analysis.DefaultDataTypeManagerService;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.exception.CancelledException;

public class FunctionSignatureParserTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private FunctionSignatureParser parser;
	private int dtChoiceCount;

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ToyProgramBuilder("test", false);
		StructureDataType s = new StructureDataType("StructA", 0);
		s.setPackingEnabled(true);
		s.add(IntegerDataType.dataType);
		builder.addDataType(s);
		program = builder.getProgram();

		DataTypeManagerService service = new DefaultDataTypeManagerService() {
			ArrayList<DataType> dtList; // assume types list will not change after requested during parse

			@Override
			public List<DataType> getSortedDataTypeList() {
				if (dtList != null) {
					return dtList;
				}
				// Default implementation only provides builtIn types which is not consistent 
				// with Tool-based service.
				dtList = new ArrayList<>(super.getSortedDataTypeList());
				program.getDataTypeManager().getAllDataTypes(dtList);
				Collections.sort(dtList, new NameComparator());
				return dtList;
			}

			@Override
			public DataType getDataType(String filterText) {
				// method only called if no results or multiple results were found.
				// Tool based implementation will prompt user, test will pick last one
				ArrayList<DataType> list = new ArrayList<>();
				program.getDataTypeManager().findDataTypes(filterText, list);
				if (list.isEmpty()) {
					return null;
				}
				int count = list.size();
				assertTrue("Expected when required to choose from multiple types", count > 1);
				++dtChoiceCount;
				return list.get(count - 1);
			}
		};

		parser = new FunctionSignatureParser(program.getDataTypeManager(), service);
	}

	private class NameComparator implements Comparator<DataType> {
		@Override
		public int compare(DataType d1, DataType d2) {
			int c = d1.getName().compareTo(d2.getName());
			if (c == 0) {
				return d1.getCategoryPath().compareTo(d2.getCategoryPath());
			}
			return c;
		}
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
	public void testParseSimple() throws Exception {
		FunctionDefinitionDataType dt = parser.parse(null, "int Bob(int a, float b)");
		assertEquals("int Bob(int a, float b)", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testParseWithFunkyFunctionName() throws Exception {
		FunctionSignature f = fun("int", "Bo<{}?>b", "int", "a", "float", "b");

		FunctionDefinitionDataType dt = parser.parse(f, "int Bo<{}?>b(int a, int b)");
		assertEquals("int Bo<{}?>b(int a, int b)", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testParseWithFunkyParamDataType() throws Exception {
		FunctionSignature f = fun("int", "Bob", "int", "a", "Bo<{()", "b");

		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(float a, Bo<{() b)");
		assertEquals("int Bob(float a, Bo<{() b)", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testParseWithFunkyParamName() throws Exception {
		FunctionSignature f = fun("int", "Bob", "int", "a()<>@", "int", "b");

		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(float a()<>@, int b)");
		assertEquals("int Bob(float a()<>@, int b)", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testParseWithFunkyReturnType() throws Exception {
		FunctionSignature f = fun("abc(d", "Bob", "int", "a");

		FunctionDefinitionDataType dt = parser.parse(f, "abc(d Bob(int a, float b)");
		assertEquals("abc(d Bob(int a, float b)", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testParseWithMultiWordCtypes() throws Exception {
		FunctionSignature f = fun("int", "Bob");

		FunctionDefinitionDataType dt =
			parser.parse(f, "signed char Bob(long long a, unsigned int b)");
		assertEquals("char Bob(longlong a, uint b)", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testSpacesNotAllowedInTypedFunctionName() {
		FunctionSignature f = fun("int", "Bob", "int", "a");

		try {
			parser.parse(f, "int bo b(int a, float b)");
			fail("parsed name with space");
		}
		catch (ParseException e) {
			assertTrue(e.getMessage().contains("Can't resolve"));
		}
		catch (CancelledException e) {
			fail("Unexpected cancellation");
		}
	}

	@Test
	public void testVarArgs() throws Exception {
		FunctionSignature f = fun("int", "Bob", "int", "a");

		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(int a, float b, ...)");
		assertTrue(dt.hasVarArgs());
		assertEquals("int Bob(int a, float b, ...)", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testNoArgs() throws Exception {
		FunctionSignature f = fun("int", "Bob", "int", "a");

		FunctionDefinitionDataType dt = parser.parse(f, "int Bob()");
		assertEquals(0, dt.getArguments().length);
	}

	@Test
	public void testVoidArgs() throws Exception {
		FunctionSignature f = fun("int", "Bob", "int", "a");

		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(void)");
		assertEquals(0, dt.getArguments().length);
	}

	@Test
	public void testMultiChoice() throws Exception {

		int txId = program.startTransaction("Add Struct");
		try {
			StructureDataType s = new StructureDataType(new CategoryPath("/Test"), "StructA", 0);
			s.setPackingEnabled(true);
			s.add(ByteDataType.dataType);
			program.getDataTypeManager().addDataType(s, null);
		}
		finally {
			program.endTransaction(txId, true);
		}

		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt = parser.parse(f, "int Foo(int, float, StructA *)");
		assertTrue(dt.getReturnType() instanceof IntegerDataType);
		assertEquals("Foo", dt.getName());
		ParameterDefinition[] args = dt.getArguments();
		assertEquals(3, args.length);
		assertTrue(args[0].getDataType() instanceof IntegerDataType);
		assertEquals("", args[0].getName());
		assertTrue(args[1].getDataType() instanceof FloatDataType);
		assertEquals("", args[1].getName());
		assertTrue(args[2].getDataType() instanceof Pointer);
		assertEquals("", args[2].getName());
		assertTrue("Expected structure choice to be made", dtChoiceCount == 1);
	}

	@Test
	public void testTypeCaching() throws Exception {
		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt = parser.parse(f, "int Foo(int, StructA, StructA)");
		assertTrue(dt.getReturnType() instanceof IntegerDataType);
		assertEquals("Foo", dt.getName());
		ParameterDefinition[] args = dt.getArguments();
		assertEquals(3, args.length);
		assertTrue(args[0].getDataType() instanceof IntegerDataType);
		assertEquals("", args[0].getName());
		assertTrue(args[1].getDataType() instanceof Structure);
		assertEquals("", args[1].getName());
		assertTrue(args[2].getDataType() instanceof Structure);
		assertEquals("", args[2].getName());
		// Only a single call to the DTM service should occur for StructA choice
		assertFalse("Unexpected datatype choice", dtChoiceCount == 1);
		assertEquals(args[1].getDataType(), args[1].getDataType());
	}

	@Test
	public void testNoParamNames() throws Exception {
		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt = parser.parse(f, "int Foo(int, float, StructA)");
		assertTrue(dt.getReturnType() instanceof IntegerDataType);
		assertEquals("Foo", dt.getName());
		ParameterDefinition[] args = dt.getArguments();
		assertEquals(3, args.length);
		assertTrue(args[0].getDataType() instanceof IntegerDataType);
		assertEquals("", args[0].getName());
		assertTrue(args[1].getDataType() instanceof FloatDataType);
		assertEquals("", args[1].getName());
		assertTrue(args[2].getDataType() instanceof Structure);
		assertEquals("", args[2].getName());
		assertFalse("Unexpected datatype choice", dtChoiceCount == 1);
	}

	@Test
	public void testMultiWordDataTypesWithNoParamNames() throws Exception {
		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt =
			parser.parse(f, "unsigned long Foo(unsigned long long, signed int, StructA)");
		assertTrue(dt.getReturnType() instanceof UnsignedLongDataType);
		assertEquals("Foo", dt.getName());
		ParameterDefinition[] args = dt.getArguments();
		assertEquals(3, args.length);
		assertTrue(args[0].getDataType() instanceof UnsignedLongLongDataType);
		assertEquals("", args[0].getName());
		assertTrue(args[1].getDataType() instanceof IntegerDataType);
		assertEquals("", args[1].getName());
		assertTrue(args[2].getDataType() instanceof Structure);
		assertEquals("", args[2].getName());
	}

	@Test
	public void testMultiWordModifiedDataTypesWithNoParamNames() throws Exception {
		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt =
			parser.parse(f, "unsigned long[3] Foo(unsigned long long *, signed int[3], StructA*)");
		assertTrue((new ArrayDataType(UnsignedLongDataType.dataType, 3, -1)).isEquivalent(
			dt.getReturnType()));
		assertEquals("Foo", dt.getName());
		ParameterDefinition[] args = dt.getArguments();
		assertEquals(3, args.length);
		assertTrue((new PointerDataType(UnsignedLongLongDataType.dataType)).isEquivalent(
			args[0].getDataType()));
		assertEquals("", args[0].getName());
		assertTrue((new ArrayDataType(IntegerDataType.dataType, 3, -1)).isEquivalent(
			args[1].getDataType()));
		assertEquals("", args[1].getName());
		assertTrue(args[2].getDataType() instanceof Pointer);
		assertEquals("", args[2].getName());
	}

	@Test
	public void testMultiWordDataTypesWithParamNames() throws Exception {
		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt =
			parser.parse(f, "unsigned long Foo(unsigned long long foo, signed int bar, StructA s)");
		assertTrue(dt.getReturnType() instanceof UnsignedLongDataType);
		assertEquals("Foo", dt.getName());
		ParameterDefinition[] args = dt.getArguments();
		assertEquals(3, args.length);
		assertTrue(args[0].getDataType() instanceof UnsignedLongLongDataType);
		assertEquals("foo", args[0].getName());
		assertTrue(args[1].getDataType() instanceof IntegerDataType);
		assertEquals("bar", args[1].getName());
		assertTrue(args[2].getDataType() instanceof Structure);
		assertEquals("s", args[2].getName());
	}

	@Test
	public void testMultiWordModifiedDataTypesWithParamNames() throws Exception {
		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt = parser.parse(f,
			"unsigned long[3] Bob(unsigned long long *foo, signed int[3] bar, StructA *s)");
		ParameterDefinition[] args = dt.getArguments();
		assertEquals(3, args.length);
		assertTrue((new PointerDataType(UnsignedLongLongDataType.dataType)).isEquivalent(
			args[0].getDataType()));
		assertEquals("foo", args[0].getName());
		assertTrue((new ArrayDataType(IntegerDataType.dataType, 3, -1)).isEquivalent(
			args[1].getDataType()));
		assertEquals("bar", args[1].getName());
		assertTrue(args[2].getDataType() instanceof Pointer);
		assertEquals("s", args[2].getName());
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
		catch (CancelledException e) {
			fail("Unexpected cancellation");
		}
	}

	@Test
	public void testUnsignedLong() throws Exception {
		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(unsigned long bob, float)");
		assertEquals("int Bob(ulong bob, float )", dt.getRepresentation(null, null, 0));

	}

	@Test
	public void testPointerNoSpaceBeforeName() throws Exception {
		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(char *bob, float)");
		assertEquals("int Bob(char * bob, float )", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testDoublePointerNoSpaceBeforeName() throws Exception {
		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(char **bob, float)");
		assertEquals("int Bob(char * * bob, float )", dt.getRepresentation(null, null, 0));
	}

	@Test
	public void testArrayPointerNoSpaceBeforeName() throws Exception {
		FunctionSignature f = fun("int", "Bob");
		FunctionDefinitionDataType dt = parser.parse(f, "int Bob(char[2] *bob, float)");
		assertEquals("int Bob(char[2] * bob, float )", dt.getRepresentation(null, null, 0));
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
