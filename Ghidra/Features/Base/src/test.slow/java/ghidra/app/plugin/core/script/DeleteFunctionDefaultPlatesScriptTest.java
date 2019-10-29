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
package ghidra.app.plugin.core.script;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.File;
import java.util.ArrayList;

import org.junit.*;

import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;

/**
 * Test for deleting default plate comments on a function
 */
public class DeleteFunctionDefaultPlatesScriptTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private File script;
	private ToyProgramBuilder builder;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();

		program = buildProgram();

		tool.addPlugin(ProgramTreePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());

		env.showTool();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		script = Application.getModuleFile("Base",
			"ghidra_scripts/DeleteFunctionDefaultPlatesScript.java").getFile(true);
		env.showTool();
	}

	private Program buildProgram() throws Exception {
		//Default Tree
		builder = new ToyProgramBuilder("Test", true, this);
		builder.createMemory(".text", "0x1001000", 0x4000);

		program = builder.getProgram();

		//make some functions
		makeFunctionAt("0x010018a0");
		makeFunctionAt("0x010018cf");
		makeFunctionAt("0x0100194b");
		makeFunctionAt("0x01001978");
		makeFunctionAt("0x01001ae3");
		makeFunctionAt("0x0100219c");

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testDeletePlates() throws Exception {
		Listing listing = program.getListing();
		ArrayList<Address> list = new ArrayList<>();
		FunctionIterator iter = program.getFunctionManager().getFunctions(true);
		while (iter.hasNext()) {
			Function f = iter.next();
			String[] comments = f.getCommentAsArray();
			if (comments != null && comments.length == 1 && comments[0].equals(" FUNCTION")) {
				list.add(f.getEntryPoint());
			}
		}
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		waitForScriptCompletion(scriptID, 1200000);

		program.flushEvents();
		waitForPostedSwingRunnables();

		for (int i = 0; i < list.size(); i++) {
			Address addr = list.get(i);
			Function f = listing.getFunctionAt(addr);
			assertNull(f.getComment());
		}
	}

	@Test
	public void testDeletePlatesOnSelection() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0x01001978), getAddr(0x01001ae2));
		set.addRange(getAddr(0x0100219c), getAddr(0x0100248e));

		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("test", new ProgramSelection(set), program));

		Listing listing = program.getListing();
		ArrayList<Address> list = new ArrayList<>();
		FunctionIterator iter = program.getFunctionManager().getFunctions(set, true);
		while (iter.hasNext()) {
			Function f = iter.next();
			String[] comments = f.getCommentAsArray();
			if (comments != null && comments.length == 1 && comments[0].equals(" FUNCTION")) {
				list.add(f.getEntryPoint());
			}
		}
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		waitForScriptCompletion(scriptID, 100000);

		program.flushEvents();
		waitForPostedSwingRunnables();

		for (int i = 0; i < list.size(); i++) {
			Address addr = list.get(i);
			Function f = listing.getFunctionAt(addr);
			assertNull(f.getComment());
		}
	}

	private Address getAddr(int offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

	private void makeFunctionAt(String addr) throws MemoryAccessException {
		builder.addBytesNOP(addr, 0x10);
		builder.disassemble(addr, 0x10, true);
		builder.createFunction(addr);
	}
}
