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
package ghidra.app.plugin.core.function;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.FunctionTestDouble;
import ghidra.program.model.TestDoubleFunctionSignature;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.test.*;

public class EditFunctionSignatureDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(DataTypeManagerPlugin.class.getName());

		ToyProgramBuilder builder = new ToyProgramBuilder("Test", true);
		program = builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testParseSignature_GoodSingleArray() throws Exception {

		String signature = "void test(int [12] a)";
		Function f = function("test", signature);
		EditFunctionSignatureDialog dialog = new EditFunctionSignatureDialog(tool, "Title", f);
		FunctionDefinitionDataType definition = dialog.parseSignature();
		assertNotNull(definition);
		assertEquals(signature, definition.getPrototypeString());
	}

	@Test
	public void testParseSignature_GoodMultiArray() throws Exception {

		String signature = "void test(int [9][4] a, char [30][10] b)";
		Function f = function("test", signature);
		EditFunctionSignatureDialog dialog = new EditFunctionSignatureDialog(tool, "Title", f);
		FunctionDefinitionDataType definition = dialog.parseSignature();
		assertNotNull(definition);
		assertEquals(signature, definition.getPrototypeString());
	}

	@Test
	public void testParseSignature_GoodMixedSizePointers() throws Exception {

		String signature = "void *32 test(int *32 a, int *24 b)";
		Function f = function("test", signature);
		EditFunctionSignatureDialog dialog = new EditFunctionSignatureDialog(tool, "Title", f);
		FunctionDefinitionDataType definition = dialog.parseSignature();
		assertNotNull(definition);
		assertEquals(signature, definition.getPrototypeString());
	}

	@Test
	public void testParseSignature_Good() throws Exception {

		String signature = "void bob(int a)";
		Function f = function("bob", signature);
		EditFunctionSignatureDialog dialog = new EditFunctionSignatureDialog(tool, "Title", f);
		FunctionDefinitionDataType definition = dialog.parseSignature();
		assertNotNull(definition);
		assertEquals(signature, definition.getPrototypeString());
	}

	@Test
	public void testParseSignature_Bad_AtSignInName() throws Exception {

		String signature = "void bob@12(int a)";
		Function f = function("bob@12", signature);
		EditFunctionSignatureDialog dialog = new EditFunctionSignatureDialog(tool, "Title", f);
		FunctionDefinitionDataType definition = dialog.parseSignature();
		assertNotNull(definition);
		assertEquals(signature, definition.getPrototypeString());
	}

	@Test
	public void testParseSignature_Bad_ExtraParensAtEnd() throws Exception {

		String signature = "void bob(int a)()";
		Function f = function("bob", signature);
		EditFunctionSignatureDialog dialog = new EditFunctionSignatureDialog(tool, "Title", f);
		FunctionDefinitionDataType definition = dialog.parseSignature();

		// bad parse, definition will be null;
		assertNull(definition);

	}

	@Test
	public void testParseSignature_Bad_MissingParen() throws Exception {

		String signature = "void bob(int a";
		Function f = function("bob", signature);
		EditFunctionSignatureDialog dialog = new EditFunctionSignatureDialog(tool, "Title", f);
		FunctionDefinitionDataType definition = dialog.parseSignature();
		assertNull(definition);
	}

	@Test
	public void testParseSignature_Bad_MissingReturnType() throws Exception {

		String signature = "bob(int a)";
		Function f = function("bob", signature);
		EditFunctionSignatureDialog dialog = new EditFunctionSignatureDialog(tool, "Title", f);
		FunctionDefinitionDataType definition = dialog.parseSignature();
		assertNull(definition);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private Function function(String name, String signature) {
		return new LocalFunctionStub(name, signature);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class LocalFunctionStub extends FunctionTestDouble {

		public LocalFunctionStub(String name, String signature) {
			super("Name", new LocalFunctionSignatureTestDouble(name, signature));
		}

		@Override
		public Program getProgram() {
			return program;
		}

		@Override
		public String getCallingConventionName() {
			return CompilerSpec.CALLING_CONVENTION_stdcall;
		}

		@Override
		public boolean isInline() {
			return false;
		}

		@Override
		public boolean isThunk() {
			return false;
		}

		@Override
		public boolean isExternal() {
			return false;
		}

		@Override
		public boolean hasNoReturn() {
			return false;
		}

	}

	private class LocalFunctionSignatureTestDouble extends TestDoubleFunctionSignature {

		public LocalFunctionSignatureTestDouble(String name, String signature) {
			super(name, signature);
		}

		@Override
		public DataType getReturnType() {
			return VoidDataType.dataType;
		}

		@Override
		public ParameterDefinition[] getArguments() {
			return new ParameterDefinition[0];
		}

	}

}
