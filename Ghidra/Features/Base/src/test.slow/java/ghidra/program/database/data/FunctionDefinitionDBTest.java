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
package ghidra.program.database.data;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class FunctionDefinitionDBTest extends AbstractGhidraHeadedIntegrationTest {
	private ProgramDB program;
	private DataTypeManagerDB dtm;
	private int transactionID;
	private FunctionDefinition functionDt;

	public FunctionDefinitionDBTest() {
		super();
	}

	private void startTransaction() {
		transactionID = program.startTransaction("Test");
	}

	private void endTransaction() {
		program.endTransaction(transactionID, true);
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		dtm = program.getDataTypeManager();
		startTransaction();
		FunctionDefinitionDataType fdt = new FunctionDefinitionDataType("test");
		fdt.setComment("My comments");
		functionDt = (FunctionDefinition) dtm.resolve(fdt, null);
	}

	@After
	public void tearDown() throws Exception {
		endTransaction();
		program.release(this);
	}

	@Test
    public void testSetArguments() throws Exception {
		ParameterDefinition[] parms = functionDt.getArguments();
		assertEquals(0, parms.length);
		addThreeArguments();
		parms = functionDt.getArguments();
		assertEquals(3, parms.length);
		assertTrue(parms[0].getDataType().isEquivalent(new ByteDataType()));
		assertTrue(parms[1].getDataType().isEquivalent(new FloatDataType()));
		assertTrue(parms[2].getDataType().isEquivalent(new CharDataType()));
		assertEquals(parms[0].getName(), "parm1");
		assertEquals(parms[1].getName(), "parm2");
		assertEquals(parms[2].getName(), "parm3");
		assertEquals(parms[0].getComment(), "this is first parm.");
		assertEquals(parms[1].getComment(), "this is second parm.");
		assertEquals(parms[2].getComment(), "this is third parm.");
	}

	private void addThreeArguments() {
		ParameterDefinition[] newParms = new ParameterDefinition[3];
		newParms[0] =
			new ParameterDefinitionImpl("parm1", new ByteDataType(), "this is first parm.");
		newParms[1] =
			new ParameterDefinitionImpl("parm2", new FloatDataType(), "this is second parm.");
		newParms[2] =
			new ParameterDefinitionImpl("parm3", new CharDataType(), "this is third parm.");
		functionDt.setArguments(newParms);
	}

	@Test
    public void testSetName() throws Exception {
		functionDt.setName("printf");
		assertEquals(functionDt.getName(), "printf");
	}

	@Test
    public void testSetComment() throws Exception {
		functionDt.setComment("My test comment.");
		assertEquals(functionDt.getComment(), "My test comment.");
	}

	@Test
    public void testSetReturnType() {
		functionDt.setReturnType(new DWordDataType());
		assertTrue(functionDt.getReturnType().isEquivalent(new DWordDataType()));
	}

	@Test
    public void testEquals() throws Exception {
		FunctionDefinitionDataType fdt = new FunctionDefinitionDataType(functionDt, dtm);
		assertEquals(functionDt, fdt);

	}

	@Test
    public void testNotEquals() throws Exception {
		FunctionDefinitionDataType fdt = new FunctionDefinitionDataType(functionDt);
		fdt.setComment("other comments");
		assertTrue(!functionDt.equals(fdt));
	}

}
