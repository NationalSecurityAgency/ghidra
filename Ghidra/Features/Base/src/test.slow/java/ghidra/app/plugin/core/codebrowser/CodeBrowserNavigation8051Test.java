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

import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.XRefFieldLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class CodeBrowserNavigation8051Test extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CodeBrowserPlugin cb;

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(LocationReferencesPlugin.class.getName());
		tool.addPlugin(MarkerManagerPlugin.class.getName());
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
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._8051);
		builder.createMemory("CODE", "CODE:0000", 0x1948);
		builder.createMemory("INTMEM", "INTMEM:20", 0xe0);
		builder.setBytes("CODE:07ea", "f5 55", true);
		builder.setBytes("CODE:03f8", "30 02 03", true);
		builder.setBytes("CODE:0595", "75 55 1b", true);

		builder.createEmptyFunction("FUN1", "CODE:03f0", 0x20, DataType.DEFAULT);
		builder.createEmptyFunction("FUN2", "CODE:07d0", 0x20, DataType.DEFAULT);
		return builder.getProgram();
	}

	@Test
	public void testOperandNavigation() throws Exception {
		loadProgram("test");
		env.showTool();
		waitForPostedSwingRunnables();
		cb.goTo(new OperandFieldLocation(program, addr("CODE:07ea"), null, null, null, 0, 0));
		assertEquals(addr("CODE:07ea"), cb.getCurrentAddress());

		click(cb, 2);
		assertEquals(addr("INTMEM:55"), cb.getCurrentAddress());

		cb.goTo(new OperandFieldLocation(program, addr("CODE:03f8"), null, null, null, 1, 0));
		assertEquals(addr("CODE:03f8"), cb.getCurrentAddress());

		click(cb, 2);
		assertEquals(addr("CODE:03fe"), cb.getCurrentAddress());

		cb.goTo(new XRefFieldLocation(program, addr("INTMEM:55"), null, addr("CODE:0595"), 1, 2));
		assertEquals(addr("INTMEM:55"), cb.getCurrentAddress());

		click(cb, 2);
		assertEquals(addr("CODE:07ea"), cb.getCurrentAddress());
	}

}
