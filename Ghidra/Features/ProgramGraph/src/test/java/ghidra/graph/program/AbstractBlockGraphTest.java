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
package ghidra.graph.program;

import org.junit.After;
import org.junit.Before;

import ghidra.app.plugin.core.blockmodel.BlockModelServicePlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.BlockModelService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.test.*;

public class AbstractBlockGraphTest extends AbstractGhidraHeadedIntegrationTest {

	protected static final String CALLER_FUNCTION_ADDRESS = "01002200";
	protected static final String SIMPLE_FUNCTION_ADDRESS = "01002239";

	protected PluginTool tool;
	protected ProgramDB program;
	protected TestEnv env;
	protected BlockModelService blockModelService;
	private ToyProgramBuilder builder;
	protected CodeBrowserPlugin codeBrowser;

	@Before
	public void setUp() throws Exception {

		setErrorGUIEnabled(false);

		env = new TestEnv();
		tool = env.getTool();

		initializeTool();
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	protected void initializeTool() throws Exception {
		installPlugins();

		openProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		showTool(tool);
		blockModelService = tool.getService(BlockModelService.class);
	}

	protected void installPlugins() throws PluginException {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(BlockModelServicePlugin.class.getName());
		codeBrowser = env.getPlugin(CodeBrowserPlugin.class);
	}

	protected void openProgram() throws Exception {

		builder = new ToyProgramBuilder("sample", true);
		builder.createMemory("caller", "0x01002200", 8);
		builder.createMemory("simple", "0x01002239", 8);
		builder.createMemory("not_graphed", "0x01002300", 8);

		buildCallerFunction();
		buildSimpleFunction();

		program = builder.getProgram();
	}

	private void buildCallerFunction() throws MemoryAccessException {
		// just a function that calls another
		builder.addBytesNOP("0x01002200", 1);
		builder.addBytesCall("0x01002201", "0x01002239");// jump to C
		builder.addBytesReturn("0x01002203");

		builder.disassemble("0x01002200", 4, true);
		builder.createFunction("0x01002200");
		builder.createLabel("0x01002200", "entry");// function label
	}

	private void buildSimpleFunction() throws MemoryAccessException {
		// just a function to render in the graph so that we can clear out settings/cache
		// 01002239

		/*
		
		 A
		 |->B
		 C
		
		
		 */

		// A
		builder.addBytesNOP("0x01002239", 1);
		builder.addBytesBranchConditional("0x0100223a", "0x0100223e");// jump to C

		// B
		builder.addBytesNOP("0x0100223c", 1);
		builder.addBytesNOP("0x0100223d", 1);// fallthrough to C

		// C
		builder.addBytesNOP("0x0100223e", 1);
		builder.addBytesReturn("0x0100223f");

		builder.disassemble("0x01002239", 8, true);
		builder.createFunction("0x01002239");
		builder.createLabel("0x01002239", "simple");// function label
	}

	protected Address addr(long addr) {
		return builder.getAddress(addr);
	}

	protected Address addr(String addressString) {
		return builder.addr(addressString);
	}

}
