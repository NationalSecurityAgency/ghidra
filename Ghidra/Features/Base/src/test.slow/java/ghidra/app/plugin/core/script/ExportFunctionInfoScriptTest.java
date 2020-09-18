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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

import docking.widgets.filechooser.GhidraFileChooser;
import generic.json.Json;
import ghidra.framework.Application;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.test.*;

/**
 * Tests the {@code ExportFunctionInfoScript}, which writes Ghidra function object info in JSON
 * form for the entire program
 */
public class ExportFunctionInfoScriptTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private File script;

	private Program program;
	private Function f1;
	private Function f2;

	@Before
	public void setUp() throws Exception {

		program = buildProgram();

		env = new TestEnv();
		env.launchDefaultTool(program);

		String scriptPath = "ghidra_scripts/ExportFunctionInfoScript.java";
		script = Application.getModuleFile("Base", scriptPath).getFile(true);
	}

	private Program buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("Test", true, this);
		builder.createMemory(".text", "0x1001000", 0x40);

		f1 = builder.createFunction("0x1001000");
		f2 = builder.createFunction("0x1001020");

		return builder.getProgram();
	}

	@Test
	public void testScript() throws Exception {

		File outputFile = createTempFileForTest();

		ScriptTaskListener listener = env.runScript(script);

		chooseFile(outputFile);

		waitForScriptCompletion(listener, 20000);

		assertFunctionsInFile(outputFile, f1, f2);
	}

	private void assertFunctionsInFile(File file, Function... functions)
			throws Exception {

		List<Function> testFunctions = new ArrayList<>(List.of(f1, f2));

		List<TestJsonFunction> jsons = readFromJson(file);

		jsons.forEach(jsonFunction -> assertFunction(jsonFunction, testFunctions));
		assertThat("Not all program functions written to json file",
			testFunctions, is(empty()));
	}

	private List<TestJsonFunction> readFromJson(File file) throws Exception {

		List<TestJsonFunction> results = new ArrayList<>();
		Gson gson = new Gson();
		BufferedReader br = new BufferedReader(new FileReader(file));
		JsonReader reader = new JsonReader(br);

		// the file is an array of objects
		reader.beginArray();
		while (reader.hasNext()) {
			TestJsonFunction function = gson.fromJson(reader, TestJsonFunction.class);
			results.add(function);
		}
		reader.endArray();
		reader.close();

		return results;
	}

	private void assertFunction(TestJsonFunction function, List<Function> testFunctions) {
		Function match = null;
		for (Function expected : testFunctions) {
			if (function.matches(expected)) {
				match = expected;
				break;
			}
		}

		assertNotNull("Unexpected function written to file", match);
		testFunctions.remove(match);
	}

	private void chooseFile(File file) throws Exception {

		GhidraFileChooser chooser = waitForDialogComponent(GhidraFileChooser.class);
		runSwing(() -> chooser.setSelectedFile(file));
		waitForUpdateOnChooser(chooser);
		pressButtonByText(chooser.getComponent(), "Choose");
		waitForSwing();
	}

	private class TestJsonFunction {
		private String name;
		private String entry;

		boolean matches(Function expected) {
			return name.equals(expected.getName()) &&
				entry.equals(expected.getEntryPoint().toString());
		}

		@Override
		public String toString() {
			// this is only for debug; not required
			return Json.toString(this);
		}

	}
}
