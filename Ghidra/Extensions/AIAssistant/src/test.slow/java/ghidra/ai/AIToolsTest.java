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
package ghidra.ai;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.stream.Collectors;

import javax.swing.JMenuBar;

import org.junit.*;

import com.google.gson.JsonObject;

import docking.i18n.UiTranslator;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.gotoquery.GoToServicePlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.*;

/**
 * Runs the AI assistant's tools against a small program, the way the model would call them.
 */
public class AIToolsTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private AIAssistantPlugin plugin;
	private CodeBrowserPlugin codeBrowser;
	private AITools tools;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("sample", true, this);
		builder.createMemory(".text", "0x1000", 0x100);

		// main: calls check_password, then returns
		builder.addBytesCall(0x1000, 0x1020);
		builder.addBytesReturn(0x1002);
		builder.disassemble("0x1000", 4);
		builder.createFunction("0x1000");

		// check_password: loads the error message, then returns
		builder.addBytesLoad(0x1020, 1, 2);
		builder.addBytesReturn(0x1022);
		builder.disassemble("0x1020", 4);
		builder.createFunction("0x1020");

		builder.createString("0x1080", "Wrong password!");
		builder.createMemoryReference("0x1020", "0x1080", RefType.READ, SourceType.USER_DEFINED);

		program = builder.getProgram();
		int tx = program.startTransaction("names");
		program.getFunctionManager().getFunctionAt(builder.addr(0x1000))
				.setName("main", SourceType.USER_DEFINED);
		program.getFunctionManager().getFunctionAt(builder.addr(0x1020))
				.setName("check_password", SourceType.USER_DEFINED);
		program.endTransaction(tx, true);

		env = new TestEnv();
		tool = env.showTool(program);
		tool.addPlugin(GoToServicePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(AIAssistantPlugin.class.getName());
		plugin = env.getPlugin(AIAssistantPlugin.class);
		codeBrowser = env.getPlugin(CodeBrowserPlugin.class);
		waitForSwing();
		tools = new AITools(plugin);
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private String run(String name, String key, String value) {
		JsonObject args = new JsonObject();
		if (key != null) {
			args.addProperty(key, value);
		}
		String result = tools.execute(name, args);
		System.out.println("--- " + name + "(" + value + ")\n" + result);
		return result;
	}

	@Test
	public void testSearchAndNavigate() {
		assertTrue(run("get_program_info", null, null).contains("Toy"));

		String functions = run("search_functions", "query", "CHECK");
		assertTrue(functions, functions.contains("check_password @ 00001020"));

		String strings = run("search_strings", "query", "wrong");
		assertTrue(strings, strings.contains("00001080") && strings.contains("Wrong password!"));

		String refs = run("get_references_to", "target", "0x1080");
		assertTrue(refs, refs.contains("00001020") && refs.contains("check_password"));

		String callers = run("get_callers", "target", "check_password");
		assertTrue(callers, callers.contains("main"));

		String callees = run("get_callees", "target", "main");
		assertTrue(callees, callees.contains("check_password"));

		String asm = run("disassemble", "target", "main");
		assertTrue(asm, asm.contains("00001000"));

		String c = run("decompile_function", "target", "00001022");
		assertTrue(c, c.contains("check_password("));

		String moved = run("go_to", "target", "check_password");
		assertTrue(moved, moved.startsWith("Moved"));
		waitForSwing();
		assertEquals(0x1020, codeBrowser.getCurrentAddress().getOffset());

		String location = run("get_current_location", null, null);
		assertTrue(location, location.contains("check_password"));

		String missing = run("decompile_function", "target", "no_such_function");
		assertTrue(missing, missing.startsWith("Error:"));
	}

	@Test
	public void testToolMenusAreTranslated() {
		UiTranslator.install();
		// re-show a window so the translator sees freshly added components
		PluginTool second = env.launchAnotherDefaultTool();
		waitForSwing();
		JMenuBar bar = second.getToolFrame().getJMenuBar();
		String menus = Arrays.stream(bar.getComponents())
				.map(c -> c instanceof javax.swing.JMenu m ? m.getText() : "")
				.collect(Collectors.joining(","));
		System.out.println("menus: " + menus);
		assertTrue(menus, menus.contains("קובץ"));
		assertTrue(menus, menus.contains("עריכה"));
	}
}
