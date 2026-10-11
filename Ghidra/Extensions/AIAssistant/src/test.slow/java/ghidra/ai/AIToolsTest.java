/* ###
 * IP: HexToCode_License
 *
 * HexToCode
 * Copyright (c) 2026 Shmuel Sinay <g47ben@gmail.com>. All rights reserved.
 *
 * Licensed under the HexToCode Restricted License; see the LICENSE file at the
 * root of this distribution. You may not use, copy, modify or distribute this
 * file except as that license allows.
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
	public void testEditsWithApproval() throws Exception {
		AITools edit = new AITools(plugin, true);
		java.util.List<String> asked = new java.util.ArrayList<>();
		edit.setApprover(d -> {
			asked.add(d);
			return d.contains("REJECT") ? AITools.Approval.NO : AITools.Approval.YES;
		});
		tools = edit;

		String unref = run("find_unreferenced_functions", null, null);
		assertTrue(unref, unref.contains("main") && !unref.contains("check_password"));

		String renamed = runArgs("rename_function", "target", "check_password", "new_name",
			"verify_password");
		assertTrue(renamed, renamed.startsWith("Done"));
		assertNotNull(program.getListing().getGlobalFunctions("verify_password").get(0));

		String rejected = runArgs("rename_function", "target", "main", "new_name", "REJECT");
		assertTrue(rejected, rejected.contains("rejected"));
		assertTrue(program.getListing().getGlobalFunctions("REJECT").isEmpty());

		String comment = runArgs("set_comment", "target", "main", "comment",
			"נקודת הכניסה של התוכנית", "type", "plate");
		assertTrue(comment, comment.startsWith("Done"));
		assertEquals("נקודת הכניסה של התוכנית",
			program.getListing().getGlobalFunctions("main").get(0).getComment());

		String sig = runArgs("set_function_signature", "target", "verify_password", "signature",
			"int verify_password(char * pw)");
		assertTrue(sig, sig.startsWith("Done"));

		String label = runArgs("create_label", "address", "0x1080", "name", "msg_wrong");
		assertTrue(label, label.startsWith("Done"));

		String patch = runArgs("patch_bytes", "address", "0x1002", "bytes", "f4 00");
		assertTrue(patch, patch.startsWith("Done"));

		String deleted = runArgs("delete_function", "target", "main");
		assertTrue(deleted, deleted.startsWith("Done"));
		assertNull(program.getFunctionManager().getFunctionAt(program.getMinAddress()
				.getNewAddress(0x1000)));

		// every change is undoable
		program.undo();
		assertNotNull(program.getFunctionManager().getFunctionAt(program.getMinAddress()
				.getNewAddress(0x1000)));
		assertEquals(7, asked.size());
	}

	private String runArgs(String name, String... kv) {
		JsonObject args = new JsonObject();
		for (int i = 0; i < kv.length; i += 2) {
			args.addProperty(kv[i], kv[i + 1]);
		}
		String result = tools.execute(name, args);
		System.out.println("--- " + name + args + "\n" + result);
		return result;
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

		// the product is branded HexToCode everywhere in the UI
		StringBuilder items = new StringBuilder();
		for (int i = 0; i < bar.getMenuCount(); i++) {
			javax.swing.JMenu m = bar.getMenu(i);
			for (int j = 0; j < m.getItemCount(); j++) {
				if (m.getItem(j) != null) {
					items.append(m.getItem(j).getText()).append('|');
				}
			}
		}
		System.out.println("menu items: " + items);
		assertTrue(items.toString(), items.toString().contains("אודות HexToCode"));
		assertFalse(items.toString(), items.toString().contains("Ghidra"));
	}
}
