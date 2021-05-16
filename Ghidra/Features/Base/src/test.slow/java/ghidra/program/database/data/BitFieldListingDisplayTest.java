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

import org.junit.*;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

public class BitFieldListingDisplayTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private int transactionID;

	private Structure struct;
	private AddressSpace space;
	private TestEnv env;
	private CodeBrowserPlugin plugin;

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram("Test", ProgramBuilder._TOY, this); // big-endian
		startTransaction();

		space = program.getAddressFactory().getDefaultAddressSpace();

		program.getMemory().createInitializedBlock("m", addr(0x1000), 0x100, (byte) 0,
			TaskMonitor.DUMMY, false);

		struct = createStructure("Test", 0);
		struct.setPackingEnabled(true);
		struct.addBitField(IntegerDataType.dataType, 3, "bf1", "Nuts");
		struct.addBitField(IntegerDataType.dataType, 24, "bf2", null);
		struct.addBitField(IntegerDataType.dataType, 4, "bf3", null);
		struct.addBitField(IntegerDataType.dataType, 12, "bf4", null);
		struct.addBitField(IntegerDataType.dataType, 3, "bf4a", null);
		struct.addBitField(IntegerDataType.dataType, 3, "bf5", null);
		struct.addBitField(IntegerDataType.dataType, 3, "b6", null);
		struct.add(new ByteDataType(), "field0", "Comment1");
		struct.add(new WordDataType(), null, "Comment2");
		struct.add(new DWordDataType(), "field3", null);
		struct.add(new ByteDataType(), "field4", "Comment4");

		program.getListing().createData(addr(0x1010), struct);
		env = new TestEnv();
		PluginTool tool = env.launchDefaultTool(program);
		plugin = getPlugin(tool, CodeBrowserPlugin.class);
	}

	private Address addr(long value) {
		return space.getAddress(value);
	}

	@After
	public void tearDown() throws Exception {
		endTransaction();
		env.dispose();
	}

	protected Structure createStructure(String name, int length) {
		return (Structure) getDataTypeManager().resolve(new StructureDataType(name, length), null);
	}

	protected DataTypeManager getDataTypeManager() {
		return program.getDataTypeManager();
	}

	private void startTransaction() {
		transactionID = program.startTransaction("Test");
	}

	private void endTransaction() {
		program.endTransaction(transactionID, true);
	}

	@Test
	public void testBitField() throws Exception {
		openStructure(addr(0x1010));
		assertMnemonic("Test", addr(0x1010), 0);
		assertMnemonic("int:3", addr(0x1010), 1);
		assertMnemonic("int:24", addr(0x1010), 2);
		assertMnemonic("int:4", addr(0x1013), 0);
		assertMnemonic("int:12", addr(0x1014), 0);
		assertMnemonic("int:3", addr(0x1015), 0);
		assertMnemonic("int:3", addr(0x1015), 1);
		assertMnemonic("int:3", addr(0x1016), 0);
		assertMnemonic("db", addr(0x1017), 0);
		assertMnemonic("dw", addr(0x1018), 0);

		System.out.println("wait");
	}

	private void assertMnemonic(String expectedValue, Address addr, int occurrence) {
		plugin.goToField(addr, "Mnemonic", occurrence, 0, 0);
		assertEquals(expectedValue, plugin.getCurrentFieldText());
	}

	private void openStructure(Address address) {
		// open the structure
		plugin.goToField(address, "+", 0, 0);
		click(plugin, 1);
		waitForSwing();

	}

}
