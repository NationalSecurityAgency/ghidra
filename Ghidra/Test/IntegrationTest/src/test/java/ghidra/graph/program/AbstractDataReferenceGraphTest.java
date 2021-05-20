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

import java.nio.charset.StandardCharsets;

import org.junit.After;
import org.junit.Before;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.*;

public class AbstractDataReferenceGraphTest extends AbstractGhidraHeadedIntegrationTest {

	protected PluginTool tool;
	protected ProgramDB program;
	protected TestEnv env;
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
	}

	protected void installPlugins() throws PluginException {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		codeBrowser = env.getPlugin(CodeBrowserPlugin.class);
	}

	protected void openProgram() throws Exception {

		builder = new ToyProgramBuilder("sample", true);
		builder.createMemory("data", "0x01000000", 64);
		builder.createMemory("caller", "0x01002200", 8);

		buildFunction();
		buildData();

		program = builder.getProgram();
	}

	private void buildData() throws Exception {
		builder.createString("0x01000000", "thing here", StandardCharsets.US_ASCII, true,
			StringDataType.dataType);
		builder.createMemoryReference("0x0100000c", "0x0100000f", RefType.DATA,
			SourceType.ANALYSIS);
		builder.createString("0x0100000f", "another thing", StandardCharsets.US_ASCII, true,
			StringDataType.dataType);
		builder.addDataType(IntegerDataType.dataType);
		builder.createMemoryReference("0x01000021", "0x0100000c", RefType.DATA,
			SourceType.ANALYSIS);

		Structure pointerStructure = new StructureDataType("pointer_thing", 0);
		pointerStructure.setPackingEnabled(true);
		pointerStructure.add(IntegerDataType.dataType, "num", null);
		pointerStructure.add(PointerDataType.dataType, "ptr", null);
		builder.addDataType(pointerStructure);
		builder.applyDataType("0x0100001d", pointerStructure);
	}

	private void buildFunction() throws MemoryAccessException {
		// just a function that calls another
		builder.createMemoryReference("0x1002200", "0x01000000", RefType.DATA, SourceType.ANALYSIS);
		builder.addBytesCall("0x01002201", "0x01002239");// jump to C
		builder.addBytesReturn("0x01002203");

		builder.disassemble("0x01002200", 4, true);
		builder.createFunction("0x01002200");
		builder.createLabel("0x01002200", "entry");// function label
	}

	protected Address addr(long addr) {
		return builder.getAddress(addr);
	}

	protected Address addr(String addressString) {
		return builder.addr(addressString);
	}

	protected AddressSet addrSet(long start, long end) {
		return new AddressSet(addr(start), addr(end));
	}
}
