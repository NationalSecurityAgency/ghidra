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
package ghidra.app.util.viewer.field;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.*;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.PointerDataType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class ArmOffcutReferenceTest extends AbstractGhidraHeadedIntegrationTest {
	private final String addressTableBytes =
		"f5 27 23 00 d9 2b 23 00 c1 2b 23 00 a9 2b 23 00 3b 30 23 00 23 30 23 00 0b 30 23 00 ed";
	private final String functionBytes =
		"10 b5 04 46 21 46 05 20 01 f0 f9 fa 00 20 21 46 bd e8 10 40 09 f0 c5 bf";
	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin cb;
	private ProgramDB program;
	private ProgramBuilder builder;

	public ArmOffcutReferenceTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		builder = new ProgramBuilder("Test", ProgramBuilder._ARM);
		builder.setBytes("0023303a", functionBytes);
		builder.disassembleArm("0023303a", functionBytes.length(), true);

		builder.setBytes("0045b390", addressTableBytes);
		builder.applyDataType("0045b390", new PointerDataType(), 7);

		program = builder.getProgram();

		env = new TestEnv();
		tool = env.showTool(program);
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		cb = env.getPlugin(CodeBrowserPlugin.class);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	private Address addr(String address) {
		AddressFactory addressFactory = program.getAddressFactory();
		return addressFactory.getAddress(address);
	}

	@Test
	public void testOffcutReferenceInLabelAndOperandFieldWithNoLabelAtInstruction() {
		assertTrue(cb.goToField(addr("0045b3a0"), OperandFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("LAB_0023303a+1", tf.getText());

		assertTrue(cb.goToField(addr("0023303a"), LabelFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("LAB_0023303a+1", tf.getText());

	}

	@Test
	public void testOffcutReferenceInLabelAndOperandFieldWithDefinedLabel() {
		builder.createLabel("0023303a", "bob");
		assertTrue(cb.goToField(addr("0045b3a0"), OperandFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("bob+1", tf.getText());

		assertTrue(cb.goToField(addr("0023303a"), LabelFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("bob+1 bob", tf.getText());

	}

	@Test
	public void testOffcutReferenceInLabelAndOperandFieldWithDefinedFunction() {
		builder.createFunction("0023303a");
		assertTrue(cb.goToField(addr("0045b3a0"), OperandFieldFactory.FIELD_NAME, 0, 1));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals("FUN_0023303a+1", tf.getText());

		assertTrue(cb.goToField(addr("0023303a"), LabelFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("FUN_0023303a+1 FUN_0023303a", tf.getText());

		builder.createLabel("0023303a", "bob");
		assertTrue(cb.goToField(addr("0045b3a0"), OperandFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("bob+1", tf.getText());

		assertTrue(cb.goToField(addr("0023303a"), LabelFieldFactory.FIELD_NAME, 0, 1));
		tf = (ListingTextField) cb.getCurrentField();
		assertEquals("bob+1 bob", tf.getText());

	}
}
