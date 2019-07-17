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
package ghidra.app.plugin.core.processors;

import static org.junit.Assert.assertEquals;

import javax.swing.JLabel;

import org.junit.*;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class InstructionInfoTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String startAddressString = "1000000";
	private static final byte[] BYTES =
		new byte[] { (byte) 0xff, 0x15, 0x10, 0x32, 0x00, 0x01, (byte) 0xff, 0x75, 0x14 };
	private TestEnv env;
	private PluginTool tool;
	private ProgramBuilder builder;
	private Program program;
	private CodeBrowserPlugin cb;

	public InstructionInfoTest() {
		super();
	}

	private Address addr(String address) {
		return program.getAddressFactory().getAddress(address);
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setupTool(tool);
		builder = new ProgramBuilder("test", ProgramBuilder._X86);
		builder.createMemory(".text", startAddressString, 0x1000);
		builder.setBytes(startAddressString, BYTES);
		builder.disassemble(startAddressString, BYTES.length);
		program = builder.getProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program);
		env.getPlugin(NextPrevAddressPlugin.class);
	}

	private void setupTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(ShowInstructionInfoPlugin.class.getName());

		cb = getPlugin(tool, CodeBrowserPlugin.class);
	}

	@After
	public void tearDown() {
		builder.dispose();
		env.dispose();
	}

	@Test
	public void testRawInstructionDisplay() {
		env.showTool();
		ShowInstructionInfoPlugin p = getPlugin(tool, ShowInstructionInfoPlugin.class);
		JLabel label = p.getInstructionLabel();

		cb.goToField(addr("0x1000000"), "Address", 0, 0);
		assertEquals(" CALL dword ptr [0x01003210] ", label.getText());
		cb.goToField(addr("0x1000006"), "Address", 0, 0);
		assertEquals(" PUSH dword ptr [EBP + 0x14] ", label.getText());
	}

}
