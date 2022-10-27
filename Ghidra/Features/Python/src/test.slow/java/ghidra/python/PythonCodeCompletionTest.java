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
package ghidra.python;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.junit.*;
import org.junit.rules.TemporaryFolder;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

/**
 * Tests for the Ghidra Python Interpreter's code completion functionality.
 */
public class PythonCodeCompletionTest extends AbstractGhidraHeadedIntegrationTest {

	private String simpleTestProgram = """
			my_int = 32
			my_bool = True
			my_string = 'this is a string'
			my_list = ["a", 2, 5.3, my_string]
			my_tuple = (1, 2, 3)
			my_dictionary = {"key1": "1", "key2": 2, "key3": my_list}
			mY_None = None
			i = 5

			def factorial(n):
			    return 1 if n == 0 else n * factorial(n-1)
			def error_function():
			    raise IOError("An IO error occurred!")

			class Employee:
			    def __init__(self, id, name):
			        self.id = id
			        self.name = name
			    def getId(self):
			        return self.id
			    def getName(self):
			        return self.name

			employee = Employee(42, "Bob")
				""".stripIndent();

	@Rule
	public TemporaryFolder tempScriptFolder = new TemporaryFolder();

	private GhidraPythonInterpreter interpreter;

	@Before
	public void setUp() throws Exception {
		GhidraScriptUtil.initialize(new BundleHost(), null);
		interpreter = GhidraPythonInterpreter.get();
		executePythonProgram(simpleTestProgram);
	}

	@After
	public void tearDown() throws Exception {
		interpreter.cleanup();
		GhidraScriptUtil.dispose();
	}

	@Test
	public void testBasicCodeCompletion() {
		// test the "insertion" field
		// it should be equal to the full name of a variable we want to complete

		List<String> completions = List.of("my_bool", "my_dictionary", "my_int", "my_list",
			"mY_None", "my_string", "my_tuple");
		assertCompletionsInclude("My", completions);
		assertCompletionsInclude("employee.Get", List.of("getId", "getName"));
		assertCompletionsInclude("('noise', (1 + fact", List.of("factorial"));
	}

	@Test
	public void testCharsToRemoveField() {
		// 'charsToRemove' field should be equal to the length of
		// a part of variable/function/method name we are trying to complete here.
		// This allows us to correctly put a completion in cases when we really
		// just want to replace a piece of text (i.e. "CURRENTAddress" => "currentAddress")
		// rather than simply 'complete' it.

		assertCharsToRemoveEqualsTo("my_int", "my_int".length());
		assertCharsToRemoveEqualsTo("employee.get", "get".length());
		assertCharsToRemoveEqualsTo("('noise', (1 + fact", "fact".length());

		assertCharsToRemoveEqualsTo("employee.", 0);
		assertCharsToRemoveEqualsTo("employee.getId(", 0);
	}

	private void assertCompletionsInclude(String command, Collection<String> expectedCompletions) {
		Set<String> completions = interpreter.getCommandCompletions(command, false)
				.stream()
				.map(c -> c.getInsertion())
				.collect(Collectors.toSet());

		var missing = new HashSet<String>(expectedCompletions);
		missing.removeAll(completions);
		if (!missing.isEmpty()) {
			Assert.fail("Could't find these completions: " + missing);
		}
	}

	private void assertCharsToRemoveEqualsTo(String command, int expectedCharsToRemove) {
		for (CodeCompletion comp : interpreter.getCommandCompletions(command, false)) {
			assertEquals(String.format("%s; field 'charsToRemove' ", comp), expectedCharsToRemove,
				comp.getCharsToRemove());
		}
	}

	private void executePythonProgram(String code) {
		try {
			File tempFile = tempScriptFolder.newFile();
			FileUtils.writeStringToFile(tempFile, code, Charset.defaultCharset());
			interpreter.execFile(new ResourceFile(tempFile), null);
		}
		catch (IOException e) {
			fail("couldn't create a test script: " + e.getMessage());
		}
	}
}
