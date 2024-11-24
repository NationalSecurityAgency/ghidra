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
package ghidra.app.plugin.core.debug.gui.tracermi.launcher;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.junit.*;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.gui.InvocationDialogHelper;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.ScriptAttributesParser.BaseType;
import ghidra.async.SwingExecutorService;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.tracermi.LaunchParameter;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.PathIsDir;
import ghidra.framework.plugintool.AutoConfigState.PathIsFile;

public class TraceRmiLaunchDialogTest extends AbstractGhidraHeadedDebuggerTest {
	private static final LaunchParameter<String> PARAM_STRING =
		BaseType.STRING.createParameter("some_string", "A String", "A string",
			true, ValStr.str("Hello"));
	private static final LaunchParameter<BigInteger> PARAM_INT =
		BaseType.INT.createParameter("some_int", "An Int", "An integer",
			true, intVal(99));
	private static final LaunchParameter<Boolean> PARAM_BOOL =
		BaseType.BOOL.createParameter("some_bool", "A Bool", "A boolean",
			true, ValStr.from(true));
	private static final LaunchParameter<Path> PARAM_PATH =
		BaseType.PATH.createParameter("some_path", "A Path", "A path",
			true, pathVal("my_path"));
	private static final LaunchParameter<PathIsDir> PARAM_DIR =
		BaseType.DIR.createParameter("some_dir", "A Dir", "A directory",
			true, dirVal("my_dir"));
	private static final LaunchParameter<PathIsFile> PARAM_FILE =
		BaseType.FILE.createParameter("some_file", "A File", "A file",
			true, fileVal("my_file"));

	private TraceRmiLaunchDialog dialog;

	@Before
	public void setupRmiLaunchDialogTest() throws Exception {
		dialog = new TraceRmiLaunchDialog(tool, "Launch Test", "Launch", null);
	}

	record PromptResult(CompletableFuture<Map<String, ValStr<?>>> args,
			InvocationDialogHelper<LaunchParameter<?>, ?> h) {}

	protected PromptResult prompt(LaunchParameter<?>... params) {
		CompletableFuture<Map<String, ValStr<?>>> args = CompletableFuture.supplyAsync(
			() -> dialog.promptArguments(LaunchParameter.mapOf(params), Map.of(), Map.of()),
			SwingExecutorService.LATER);
		InvocationDialogHelper<LaunchParameter<?>, ?> helper =
			InvocationDialogHelper.waitFor(TraceRmiLaunchDialog.class);
		return new PromptResult(args, helper);
	}

	static ValStr<BigInteger> intVal(long val, String str) {
		return new ValStr<>(BigInteger.valueOf(val), str);
	}

	static ValStr<BigInteger> intVal(long val) {
		return ValStr.from(BigInteger.valueOf(val));
	}

	static ValStr<Path> pathVal(String path) {
		return new ValStr<>(Paths.get(path), path);
	}

	static ValStr<PathIsDir> dirVal(String path) {
		return new ValStr<>(PathIsDir.fromString(path), path);
	}

	static ValStr<PathIsFile> fileVal(String path) {
		return new ValStr<>(PathIsFile.fromString(path), path);
	}

	@Test
	public void testStringDefaultValue() throws Throwable {
		PromptResult result = prompt(PARAM_STRING);
		result.h.invoke();

		Map<String, ValStr<?>> args = waitOn(result.args);
		assertEquals(Map.of("some_string", ValStr.str("Hello")), args);
	}

	@Test
	public void testStringInputValue() throws Throwable {
		PromptResult result = prompt(PARAM_STRING);
		result.h.setArgAsString(PARAM_STRING, "World");
		result.h.invoke();

		Map<String, ValStr<?>> args = waitOn(result.args);
		assertEquals(Map.of("some_string", ValStr.str("World")), args);
	}

	@Test
	public void testIntDefaultValue() throws Throwable {
		PromptResult result = prompt(PARAM_INT);
		result.h.invoke();

		Map<String, ValStr<?>> args = waitOn(result.args);
		assertEquals(Map.of("some_int", intVal(99)), args);
	}

	@Test
	public void testIntInputHexValue() throws Throwable {
		PromptResult result = prompt(PARAM_INT);
		result.h.setArgAsString(PARAM_INT, "0x11");
		result.h.invoke();

		Map<String, ValStr<?>> args = waitOn(result.args);
		assertEquals(Map.of("some_int", intVal(17, "0x11")), args);
	}

	@Test
	public void testIntInputHexValueIncomplete() throws Throwable {
		PromptResult result = prompt(PARAM_INT);
		try {
			result.h.setArgAsString(PARAM_INT, "0x");
			fail();
		}
		catch (NumberFormatException e) {
			// pass
		}
		result.h.invoke();
	}

	@Test
	public void testIntSaveHexValue() throws Throwable {
		PromptResult result = prompt(PARAM_INT);
		result.h.setArgAsString(PARAM_INT, "0x11");
		result.h.invoke();

		SaveState state = result.h.saveState();
		assertEquals("0x11", state.getString("some_int,java.math.BigInteger", null));
	}

	@Test
	@Ignore
	public void testIntLoadHexValue() throws Throwable {
		/**
		 * TODO: This is a bit out of order. However, the dialog cannot load/decode from the state
		 * until it has the parameters. Worse, to check that user input was valid, the dialog
		 * verifies that the value it gets back matches the text in the box, because if it doesn't,
		 * then the editor must have failed to parse/decode the value. Currently, loading the state
		 * while the dialog box has already populated its values, does not modify the contents of
		 * any editor, so the text <em>will not</em> match, causing this test to fail.
		 */
		PromptResult result = prompt(PARAM_INT);
		SaveState state = new SaveState();
		state.putString("some_int,java.math.BigInteger", "0x11");
		result.h.loadState(state);
		result.h.invoke();

		Map<String, ValStr<?>> args = waitOn(result.args);
		assertEquals(Map.of("some_int", intVal(17, "0x11")), args);
	}

	@Test
	public void testBoolDefaultValue() throws Throwable {
		PromptResult result = prompt(PARAM_BOOL);
		result.h.invoke();

		Map<String, ValStr<?>> args = waitOn(result.args);
		assertEquals(Map.of("some_bool", ValStr.from(true)), args);
	}

	@Test
	public void testBoolInputValue() throws Throwable {
		PromptResult result = prompt(PARAM_BOOL);
		result.h.setArg(PARAM_BOOL, false);
		result.h.invoke();

		Map<String, ValStr<?>> args = waitOn(result.args);
		assertEquals(Map.of("some_bool", ValStr.from(false)), args);
	}

	@Test
	public void testPathDefaultValue() throws Throwable {
		PromptResult result = prompt(PARAM_PATH);
		result.h.invoke();

		Map<String, ValStr<?>> args = waitOn(result.args);
		assertEquals(Map.of("some_path", pathVal("my_path")), args);
	}

	@Test
	public void testPathInputValue() throws Throwable {
		PromptResult result = prompt(PARAM_PATH);
		result.h.setArgAsString(PARAM_PATH, "your_path");
		result.h.invoke();

		Map<String, ValStr<?>> args = waitOn(result.args);
		assertEquals(Map.of("some_path", pathVal("your_path")), args);
	}

	@Test
	public void testDirDefaultValue() throws Throwable {
		PromptResult result = prompt(PARAM_DIR);
		result.h.invoke();

		Map<String, ValStr<?>> args = waitOn(result.args);
		assertEquals(Map.of("some_dir", dirVal("my_dir")), args);
	}

	@Test
	public void testDirInputValue() throws Throwable {
		PromptResult result = prompt(PARAM_DIR);
		result.h.setArgAsString(PARAM_DIR, "your_dir");
		result.h.invoke();

		Map<String, ValStr<?>> args = waitOn(result.args);
		assertEquals(Map.of("some_dir", dirVal("your_dir")), args);
	}

	@Test
	public void testFileDefaultValue() throws Throwable {
		PromptResult result = prompt(PARAM_FILE);
		result.h.invoke();

		Map<String, ValStr<?>> args = waitOn(result.args);
		assertEquals(Map.of("some_file", fileVal("my_file")), args);
	}

	@Test
	public void testFileInputValue() throws Throwable {
		PromptResult result = prompt(PARAM_FILE);
		result.h.setArgAsString(PARAM_FILE, "your_file");
		result.h.invoke();

		Map<String, ValStr<?>> args = waitOn(result.args);
		assertEquals(Map.of("some_file", fileVal("your_file")), args);
	}
}
