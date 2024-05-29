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
package ghidra.app.plugin.compare;

import static org.junit.Assert.*;

import java.util.Set;

import org.junit.*;

import ghidra.app.plugin.core.functioncompare.*;
import ghidra.codecompare.decompile.CDisplay;
import ghidra.codecompare.decompile.DecompilerCodeComparisonPanel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.test.*;

/**
 * Tests for the {@link FunctionComparisonPlugin function comparison plugin}
 * that involve the GUI
 */
public class CompareFunctionsDecompilerViewTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program1;
	private Function fun1;
	private Function fun2;
	private FunctionComparisonPlugin plugin;
	private FunctionComparisonProvider provider;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		plugin = env.addPlugin(FunctionComparisonPlugin.class);
		program1 = buildTestProgram();
		showTool(plugin.getTool());
		env.open(program1);
		FunctionManager functionManager = program1.getFunctionManager();
		fun1 = functionManager.getFunctionAt(addr(0x01002cf5));
		fun2 = functionManager.getFunctionAt(addr(0x0100415a));

	}

	private Address addr(long offset) {
		return program1.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testDecompDifView() throws Exception {
		Set<Function> functions = CompareFunctionsTestUtility.getFunctionsAsSet(fun1, fun2);
		provider = compareFunctions(functions);

		CompareFunctionsTestUtility.checkSourceFunctions(provider, fun1, fun2);
		DecompilerCodeComparisonPanel panel =
			(DecompilerCodeComparisonPanel) provider
					.getCodeComparisonPanelByName(DecompilerCodeComparisonPanel.NAME);

		waitForDecompiler(panel);
		assertHasLines(panel.getLeftPanel(), 28);
		assertHasLines(panel.getRightPanel(), 23);
	}

	private void assertHasLines(CDisplay panel, int lineCount) {
		assertEquals(lineCount, panel.getDecompilerPanel().getLines().size());
	}

	private void waitForDecompiler(DecompilerCodeComparisonPanel panel) {
		waitForSwing();
		waitForCondition(() -> !panel.isBusy());
		waitForSwing();
	}

	private FunctionComparisonProvider compareFunctions(Set<Function> functions) {
		provider = runSwing(() -> plugin.compareFunctions(functions));
		provider.setVisible(true);
		waitForSwing();
		return provider;
	}

	private Program buildTestProgram() throws Exception {
		ClassicSampleX86ProgramBuilder builder =
			new ClassicSampleX86ProgramBuilder("Test", false);
		return builder.getProgram();
	}

}
