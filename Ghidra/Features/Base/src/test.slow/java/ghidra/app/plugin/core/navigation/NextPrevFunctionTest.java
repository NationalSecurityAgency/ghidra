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
package ghidra.app.plugin.core.navigation;

import static org.junit.Assert.*;

import org.junit.*;

import docking.action.DockingActionIf;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.*;
import ghidra.util.exception.InvalidInputException;

public class NextPrevFunctionTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private ToyProgramBuilder builder;
	private Program program;
	private CodeBrowserPlugin cb;

	private DockingActionIf direction;
	private DockingActionIf nextFunction;

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	@SuppressWarnings("unchecked") // we know that bookmarks is of type String
	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		loadProgram();
		tool = env.launchDefaultTool(program);

		NextPrevCodeUnitPlugin p = getPlugin(tool, NextPrevCodeUnitPlugin.class);
		direction = getAction(p, "Toggle Search Direction");
		nextFunction = getAction(p, "Next Function");
		cb = env.getPlugin(CodeBrowserPlugin.class);
		goTo(program.getMinAddress());
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private void loadProgram() throws Exception {
		builder = new ToyProgramBuilder("Test", true, ProgramBuilder._TOY);

		builder.createMemory("block1", "0x100", 0x100);
		builder.createMemory("block2", "0x300", 0x100);

		builder.createFunction("0x150");
		builder.createFunction("0x250");
		builder.createFunction("0x350");

		program = builder.getProgram();
		createFunctionNotInMemory();

		addrFactory = program.getAddressFactory();
	}

	private void createFunctionNotInMemory() {
		// have to do this directly as the create function command won't let you 
		// create a function where there is no memory defined
		Address entry = builder.addr(0x250);
		AddressSet body = new AddressSet(entry);
		builder.withTransaction(() -> {
			try {
				program.getListing()
						.createFunction("notInMemoryFunction", null, entry, body,
							SourceType.USER_DEFINED);
			}
			catch (InvalidInputException | OverlappingFunctionException e) {
				e.printStackTrace();
			}
		});
	}

	@Test
	public void testNextFuctionWithMemoryGaps() throws Exception {

		assertAddress("0x100");

		performAction(nextFunction, cb.getProvider(), true);
		assertAddress("0x150");

		// the next function is at 0x250, but it isn't in memory, so make sure we don't get
		// stuck at current address and moves on the then next one that IS in memory.
		performAction(nextFunction, cb.getProvider(), true);
		assertAddress("0x350");

		toggleDirection();

		performAction(nextFunction, cb.getProvider(), true);
		assertAddress("0x150");
		performAction(nextFunction, cb.getProvider(), true);

		// no more functions, this is the last range
		assertAddress("0x150");
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void assertAddress(String addrString) {
		assertEquals(addr(addrString), cb.getCurrentAddress());
	}

	private void toggleDirection() {
		performAction(direction, cb.getProvider(), true);
	}

	private void goTo(Address a) throws Exception {
		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(a);
		cb.updateNow();
		waitForSwing();
	}
}
