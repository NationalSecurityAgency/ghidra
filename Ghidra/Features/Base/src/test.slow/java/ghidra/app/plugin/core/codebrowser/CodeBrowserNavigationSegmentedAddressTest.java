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

import docking.action.DockingActionIf;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.XRefFieldLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class CodeBrowserNavigationSegmentedAddressTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CodeBrowserPlugin cb;
	private DockingActionIf prev;
	private DockingActionIf clearHistory;
	private DockingActionIf nextFunction;
	private DockingActionIf prevFunction;

	public CodeBrowserNavigationSegmentedAddressTest() {
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
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(LocationReferencesPlugin.class.getName());
		tool.addPlugin(MarkerManagerPlugin.class.getName());
		NextPrevAddressPlugin np = env.getPlugin(NextPrevAddressPlugin.class);
		prev = getAction(np, "Previous Location in History");
		clearHistory = getAction(np, "Clear History Buffer");
		cb = env.getPlugin(CodeBrowserPlugin.class);
		nextFunction = getAction(cb, "Go to next function");
		prevFunction = getAction(cb, "Go to previous function");
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
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._X86_16_REAL_MODE);
		builder.createMemory("Seg_0", "1000:0000", 0x32c0);
		builder.createMemory("Seg_1", "132c:0000", 0x9be);
		builder.setBytes("1000:03ea", "7e 09");
		builder.disassemble("1000:03ea", 2);

		builder.setBytes("1000:0154", "ff 36 84 00");
		builder.disassemble("1000:0154", 4);

		builder.applyDataType("132c:0084", new WordDataType(), 1);
		builder.createMemoryReference("1000:0154", "132c:0084", RefType.DATA, SourceType.ANALYSIS);

		return builder.getProgram();
	}

	@Test
	public void testOperandNavigationInSegmented() throws Exception {
		loadProgram("login");
		env.showTool();
		waitForPostedSwingRunnables();
		cb.goTo(new OperandFieldLocation(program, addr("1000:03ea"), null, null, null, 0, 0));
		assertEquals(addr("1000:03ea"), cb.getCurrentAddress());

		click(cb, 2);
		assertEquals(addr("1000:3f5"), cb.getCurrentAddress());

		cb.goTo(new XRefFieldLocation(program, addr("132c:0084"), null, addr("1000:0154"), 0, 2));
		assertEquals(addr("132c:0084"), cb.getCurrentAddress());

		click(cb, 2);
		assertEquals(addr("1000:0154"), cb.getCurrentAddress());

	}

}
