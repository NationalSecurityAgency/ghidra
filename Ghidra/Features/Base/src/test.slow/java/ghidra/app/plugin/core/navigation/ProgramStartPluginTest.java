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

import ghidra.GhidraOptions;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class ProgramStartPluginTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private CodeBrowserPlugin cb;
	private Options options;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.launchDefaultTool();
		cb = env.getPlugin(CodeBrowserPlugin.class);
		options = tool.getOptions(GhidraOptions.NAVIGATION_OPTIONS);

	}

	@After
	public void tearDown() {
		env.closeTool(tool);
		env.dispose();
	}

	@Test
	public void testOpensToStartingSymbolByDefault() throws Exception {
		ProgramBuilder builder = getProgramBuilder("0x100");
		builder.createLabel("0x105", "main");
		loadProgram(builder.getProgram());

		assertEquals(addr("0x105"), cb.getCurrentAddress());
	}

	@Test
	public void testOpensToLowestCodeBlock() throws Exception {
		ProgramBuilder builder = getProgramBuilder("0x100");
		MemoryBlock block = builder.createMemory(".text", "0x200", 0x200);
		builder.setExecute(block, true);
		builder.createLabel("0x105", "main");

		setOptionToLowestCodeBlock();

		loadProgram(builder.getProgram());

		assertEquals(addr("0x200"), cb.getCurrentAddress());
	}

	@Test
	public void testOpensToStartingSymbolNotFirstInSymbolList() throws Exception {
		ProgramBuilder builder = getProgramBuilder("0x100");
		setSymbolListOption("main, foobar, start");
		builder.createLabel("0x107", "start");

		loadProgram(builder.getProgram());

		assertEquals(addr("0x107"), cb.getCurrentAddress());
	}

	@Test
	public void testOpensToFirstSymbolWhenMutlipesAreFoud() throws Exception {
		ProgramBuilder builder = getProgramBuilder("0x100");
		setSymbolListOption("main, start");
		builder.createLabel("0x110", "start");
		builder.createLabel("0x105", "start");

		loadProgram(builder.getProgram());

		assertEquals(addr("0x105"), cb.getCurrentAddress());
	}

	@Test
	public void testOpensToStartingSymbolWithOneUndercore() throws Exception {
		ProgramBuilder builder = getProgramBuilder("0x100");
		setSymbolListOption("main, start");
		builder.createLabel("0x105", "_main");
		builder.createLabel("0x107", "start");

		loadProgram(builder.getProgram());

		assertEquals(addr("0x105"), cb.getCurrentAddress());
	}

	@Test
	public void testOpensToStartingSymbolWithTwoUndercores() throws Exception {
		ProgramBuilder builder = getProgramBuilder("0x100");
		setSymbolListOption("main, start");
		builder.createLabel("0x105", "__main");
		builder.createLabel("0x107", "_start");
		builder.createLabel("0x109", "start");

		loadProgram(builder.getProgram());

		assertEquals(addr("0x105"), cb.getCurrentAddress());
	}

	@Test
	public void testNoUnderscoresSearching() throws Exception {
		ProgramBuilder builder = getProgramBuilder("0x100");
		setSymbolListOption("main, start");
		setUnderscoreOption(false);
		builder.createLabel("0x105", "__main");
		builder.createLabel("0x107", "_start");
		builder.createLabel("0x109", "start");

		loadProgram(builder.getProgram());

		assertEquals(addr("0x109"), cb.getCurrentAddress());
	}

	@Test
	public void testOptionToStartAtLowestAddress() throws Exception {
		ProgramBuilder builder = getProgramBuilder("0x100");
		builder.createLabel("0x105", "main");
		setOptionToLowestAddress();
		loadProgram(builder.getProgram());

		assertEquals(addr("0x100"), cb.getCurrentAddress());
	}

	private void setUnderscoreOption(boolean b) {
		options.setBoolean(ProgramStartingLocationOptions.UNDERSCORE_OPTION, b);
	}

	private void setOptionToLowestAddress() {
		options.setEnum(ProgramStartingLocationOptions.START_LOCATION_TYPE_OPTION,
			ProgramStartingLocationOptions.StartLocationType.LOWEST_ADDRESS);
	}

	private void setOptionToLowestCodeBlock() {
		options.setEnum(ProgramStartingLocationOptions.START_LOCATION_TYPE_OPTION,
			ProgramStartingLocationOptions.StartLocationType.LOWEST_CODE_BLOCK);
	}

	private void setSymbolListOption(String symbolListString) {
		options.setString(ProgramStartingLocationOptions.START_SYMBOLS_OPTION, symbolListString);
	}

	private ProgramBuilder getProgramBuilder(String baseAddress) throws Exception {
		ProgramBuilder builder = new ProgramBuilder();
		builder.createMemory(".data", baseAddress, 0x100);
		return builder;
	}

	private void loadProgram(Program program) throws Exception {
		env.open(program);
		addrFactory = program.getAddressFactory();
		waitForSwing();
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}
}
