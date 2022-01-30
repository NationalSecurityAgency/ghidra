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
package ghidra.app.plugin.core.analysis;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class MicrosoftDemanglerAnalyzerTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private MicrosoftDemanglerAnalyzer analyzer = new MicrosoftDemanglerAnalyzer();

	private MessageLog log = new MessageLog() {

		// overridden to prevent stack traces from appearing in the console
		@Override
		public void appendException(Throwable t) {
			appendMsg(t.toString());
		}
	};

	@Before
	public void setUp() throws Exception {

		ProgramBuilder builder = new ToyProgramBuilder("test", true);
		builder.createMemory(".text", "0x0100", 0x100);
		program = builder.getProgram();
		registerOptions();
	}

	@Override
	protected void testFailed(Throwable e) {
		Msg.error(this, "Test failed - analysis log:\n" + log);
	}

	@Test
	public void testOptions__ApplyFunctionSignature() throws Exception {

		String mangled = "?InvokeHelperV@COleDispatchDriver@@QAEXJGGPAXPBEPAD@Z";

		Address addr = addr("0x110");
		createSymbol(addr, mangled);

		setOption(MicrosoftDemanglerAnalyzer.OPTION_NAME_APPLY_SIGNATURE, true);

		analyze();

		FunctionManager fm = program.getFunctionManager();
		Function function = fm.getFunctionAt(addr);
		assertNotNull(function);
		assertTrue("Funciton signature not applied", function.getParameterCount() > 0);
	}

	@Test
	public void testOptions__DoNotApplyFunctionSignature() throws Exception {

		String mangled = "?InvokeHelperV@COleDispatchDriver@@QAEXJGGPAXPBEPAD@Z";

		Address addr = addr("0x110");
		createSymbol(addr, mangled);

		setOption(MicrosoftDemanglerAnalyzer.OPTION_NAME_APPLY_SIGNATURE, false);

		analyze();

		FunctionManager fm = program.getFunctionManager();
		Function function = fm.getFunctionAt(addr);
		assertNotNull(function);
		assertEquals("undefined InvokeHelperV(void)", function.getSignature().toString());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void analyze() {
		tx(program, () -> analyzer.added(program, program.getMemory(), TaskMonitor.DUMMY, log));
	}

	private void setOption(String optionName, boolean doUse) {

		String fullOptionName = analyzer.getName() + Options.DELIMITER_STRING + optionName;
		Options options = program.getOptions("Analyzers");

		for (String name : options.getOptionNames()) {
			if (name.equals(fullOptionName)) {
				tx(program, () -> options.setBoolean(optionName, doUse));

				// we must call this manually, since we are not using a tool
				analyzer.optionsChanged(options, program);
				return;
			}
		}

		fail("Could not find option '" + optionName + "'");
	}

	private void registerOptions() {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		Options analyzerOptions = options.getOptions(analyzer.getName());
		analyzer.registerOptions(analyzerOptions, program);
	}

	private void createSymbol(Address addr, String mangled) {
		AddLabelCmd cmd = new AddLabelCmd(addr, mangled, SourceType.ANALYSIS);
		applyCmd(program, cmd);
	}

	private Address addr(String addr) {
		return program.getAddressFactory().getAddress(addr);
	}
}
