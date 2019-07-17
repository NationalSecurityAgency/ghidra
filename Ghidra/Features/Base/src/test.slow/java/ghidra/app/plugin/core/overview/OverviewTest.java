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
package ghidra.app.plugin.core.overview;

import static org.junit.Assert.*;

import java.awt.Color;
import java.awt.Dimension;
import java.math.BigInteger;

import org.junit.*;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.overview.addresstype.AddressType;
import ghidra.app.plugin.core.overview.addresstype.AddressTypeOverviewColorService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class OverviewTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private OverviewColorPlugin plugin;
	private AddressTypeOverviewColorService service;
	private OverviewColorComponent component;

	public OverviewTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setUpCodeBrowserTool();
		tool.addPlugin(OverviewColorPlugin.class.getName());
		plugin = env.getPlugin(OverviewColorPlugin.class);

		loadProgram("test");
		env.showTool();
		runSwing(() -> env.getTool().getToolFrame().setSize(new Dimension(1024, 768)));

		service = new AddressTypeOverviewColorService();

		runSwing(() -> {
			plugin.installOverview(service);
		});
		component = (OverviewColorComponent) getInstanceField("overviewComponent", service);
	}

	private void setUpCodeBrowserTool() throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private Program buildProgram(String programName) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(programName, ProgramBuilder._TOY);
		builder.createMemory("test1", "0x1001000", 0x6000);
		Address addr = builder.addr("0x1001000");
		for (int i = 0; i < 0x1000; i++) {
			builder.applyDataType(addr.toString(), new ByteDataType());
			addr = addr.next();
		}
		builder.disassemble("0x1002000", 0x1000);
		builder.createEmptyFunction("ZZZ", "0x1003000", 1000, new ByteDataType());
		return builder.getProgram();
	}

	private void loadProgram(String programName) throws Exception {
		program = buildProgram(programName);
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		addrFactory = program.getAddressFactory();

	}

	@Test
	public void testColors() {
		Color[] colors = (Color[]) getInstanceField("colors", component);

		for (int i = 0; i < colors.length; i++) {
			Address curAddr = getAddress(i, colors);
			Color curColor = colors[i];

			if (curColor == service.getColor(AddressType.INSTRUCTION)) {
				assertNotNull(program.getListing().getInstructionContaining(curAddr));
			}
			else if (curColor == service.getColor(AddressType.DATA)) {
				assertEquals(program.getListing().getDataContaining(curAddr).isDefined(), true);
			}
			else if (curColor == service.getColor(AddressType.FUNCTION)) {
				assertNotNull(program.getListing().getFunctionContaining(curAddr));
			}
			else if (curColor == service.getColor(AddressType.UNDEFINED)) {
				assertNull(program.getListing().getInstructionContaining(curAddr));
				assertEquals(program.getListing().getDataContaining(curAddr).isDefined(), false);
			}
			else if (curColor == service.getColor(AddressType.UNINITIALIZED)) {
				assertTrue(!program.getMemory().getBlock(curAddr).isInitialized());
			}
		}
	}

	private Address getAddress(int pixelIndex, Color[] colors) {
		AddressIndexMap map = (AddressIndexMap) getInstanceField("map", component);
		BigInteger bigHeight = BigInteger.valueOf(colors.length);
		BigInteger bigPixelIndex = BigInteger.valueOf(pixelIndex);
		BigInteger bigIndex = map.getIndexCount().multiply(bigPixelIndex).divide(bigHeight);
		return map.getAddress(bigIndex);
	}

}
