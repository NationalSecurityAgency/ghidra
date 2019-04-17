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
package ghidra.app.plugin.core.codebrowser;

import static org.junit.Assert.assertEquals;

import org.junit.*;

import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.VariableNameFieldLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class CodeBrowserNavigationx86Test extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CodeBrowserPlugin cb;

	public CodeBrowserNavigationx86Test() {
		super();
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

    @Before
    public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(LocationReferencesPlugin.class.getName());
		cb = env.getPlugin(CodeBrowserPlugin.class);
	}

    @After
    public void tearDown() {
		env.dispose();
	}

	private void loadProgram(String programName) throws Exception {
		program = buildProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		addrFactory = program.getAddressFactory();
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._X86);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);
		builder.setBytes("1002cf5", "55 8b ec 83 7d 14 00 c2 14 00");
		builder.disassemble("1002cf5", 10);
		DataType dt = new DWordDataType();
		ParameterImpl param = new ParameterImpl(null, dt, builder.getProgram());
		builder.createEmptyFunction("ghidra", "1002cf5", 20, DataType.DEFAULT, param, param, param,
			param, param, param);
		builder.createStackReference("1002cf8", RefType.DATA, 0x14, SourceType.ANALYSIS, 0);
		return builder.getProgram();
	}

@Test
    public void testStackReferenceNavigation() throws Exception {
		loadProgram("notepad");
		env.showTool();
		waitForPostedSwingRunnables();
		cb.goTo(new OperandFieldLocation(program, addr("1002cf8"), null, null, null, 0, 0));
		assertEquals(addr("1002cf8"), cb.getCurrentAddress());

		click(cb, 2);
		assertEquals(addr("1002cf5"), cb.getCurrentAddress());
		VariableNameFieldLocation loc = (VariableNameFieldLocation) cb.getCurrentLocation();
		Variable var = loc.getVariable();

		assertEquals(20, var.getStackOffset());
		assertEquals("param_5", var.getName());

	}
}
