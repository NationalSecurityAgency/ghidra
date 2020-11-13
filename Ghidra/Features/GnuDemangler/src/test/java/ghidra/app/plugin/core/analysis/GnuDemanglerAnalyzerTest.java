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

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.util.demangler.gnu.GnuDemanglerOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.task.TaskMonitor;

public class GnuDemanglerAnalyzerTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramDB program;
	private GnuDemanglerAnalyzer analyzer = new GnuDemanglerAnalyzer();

	// overridden to prevent stack traces from appearing in the console
	private MessageLog log = new MessageLog() {
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
	public void testDeprectedMangledString_WithoutDeprecatedDemangler() throws Exception {

		//
		// The below demangles to MsoDAL::VertFrame::__dt( (void))
		// note the (void) syntax
		//
		// from program Microsoft Entourage
		//
		String mangled = "__dt__Q26MsoDAL9VertFrameFv";

		Address addr = addr("0x110");
		createSymbol(addr, mangled);

		setOption(GnuDemanglerAnalyzer.OPTION_NAME_USE_DEPRECATED_DEMANGLER, false);

		analyze();

		assertNotDemangled(addr, "__dt");
	}

	@Test
	public void testDeprectedMangledString_WithDeprecatedDemangler() throws Exception {

		//
		// The below demangles to MsoDAL::VertFrame::__dt( (void))
		// note the (void) syntax
		//
		// from program Microsoft Entourage
		//
		String mangled = "__dt__Q26MsoDAL9VertFrameFv";

		Address addr = addr("0x110");
		createSymbol(addr, mangled);

		setOption(GnuDemanglerAnalyzer.OPTION_NAME_USE_DEPRECATED_DEMANGLER, true);

		analyze();

		assertDemangled(addr, "__dt");
	}

	@Test
	public void testMangledString_WithArguments_Valid() {

		//
		// The below demangles to std::io::Read::read_to_end
		//
		String mangled = "_ZN3std2io4Read11read_to_end17hb85a0f6802e14499E";

		Address addr = addr("0x110");
		createSymbol(addr, mangled);

		setOption(GnuDemanglerAnalyzer.OPTION_NAME_DEMANGLER_PARAMETERS, "-s rust");

		analyze();

		assertDemangled(addr, "read_to_end");
	}

	@Test
	public void testMangledString_WithArguments_ValidButWrongFormat() {

		//
		// The below demangles to std::io::Read::read_to_end
		//
		String mangled = "_ZN3std2io4Read11read_to_end17hb85a0f6802e14499E";

		Address addr = addr("0x110");
		createSymbol(addr, mangled);

		setOption(GnuDemanglerAnalyzer.OPTION_NAME_DEMANGLER_PARAMETERS, "-s dlang");

		analyze();

		assertNotDemangled(addr, "read_to_end");
	}

	@Test
	public void testMangledString_WithArguments_Invalid() {

		//
		// The below demangles to std::io::Read::read_to_end
		//
		String mangled = "_ZN3std2io4Read11read_to_end17hb85a0f6802e14499E";

		Address addr = addr("0x110");
		createSymbol(addr, mangled);

		setOption(GnuDemanglerAnalyzer.OPTION_NAME_DEMANGLER_PARAMETERS, "-s badformatname");

		analyze();

		assertNotDemangled(addr, "read_to_end");
		assertMessageLogLine("java.io.IOException: Error starting demangler with command");
		assertMessageLogLine("Invalid options", GnuDemanglerOptions.GNU_DEMANGLER_V2_33_1);
	}

	@Test
	public void testDeprecatedMangledString_WithArguments_Invalid() {

		//
		// The below demangles to std::io::Read::read_to_end
		//
		String mangled = "_ZN3std2io4Read11read_to_end17hb85a0f6802e14499E";

		Address addr = addr("0x110");
		createSymbol(addr, mangled);

		setOption(GnuDemanglerAnalyzer.OPTION_NAME_USE_DEPRECATED_DEMANGLER, true);
		setOption(GnuDemanglerAnalyzer.OPTION_NAME_DEMANGLER_PARAMETERS, "-s badformatname");

		analyze();

		assertNotDemangled(addr, "read_to_end");
		assertMessageLogLine("java.io.IOException: Error starting demangler with command");
		assertMessageLogLine("Invalid options", GnuDemanglerOptions.GNU_DEMANGLER_V2_33_1);
		assertMessageLogLine("Invalid options", GnuDemanglerOptions.GNU_DEMANGLER_V2_24);
	}

	@Test
	public void testDeprecatedMangledString_WithArguments_InvalidModernArguments_ValidDeprecatedArguments() {

		//
		// The below demangles to std::io::Read::read_to_end
		//
		String mangled = "_ZN3std2io4Read11read_to_end17hb85a0f6802e14499E";

		Address addr = addr("0x110");
		createSymbol(addr, mangled);

		setOption(GnuDemanglerAnalyzer.OPTION_NAME_USE_DEPRECATED_DEMANGLER, true);
		setOption(GnuDemanglerAnalyzer.OPTION_NAME_DEMANGLER_PARAMETERS, "-s arm");

		analyze();

		assertNotDemangled(addr, "read_to_end");
		assertMessageLogLine("java.io.IOException: Error starting demangler with command");
		assertMessageLogLine("Invalid options", GnuDemanglerOptions.GNU_DEMANGLER_V2_33_1);
		assertMessageNotInLogLine("Invalid options", GnuDemanglerOptions.GNU_DEMANGLER_V2_24);
	}

	// things missed:
	// -demangle error case in base class...this is OK
	// -error case in applyTo method in base class

	// -use deprecated demangler case in validateOptions

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void assertMessageLogLine(String... expected) {

		String allMessages = log.toString();
		String[] logLines = allMessages.split("\n");
		for (String line : logLines) {
			if (StringUtilities.containsAllIgnoreCase(line, expected)) {
				return;
			}
		}

		fail("The folllowing source text did not have a line containing:\n" +
			Arrays.toString(expected) + "\n\nActual Text:\n" + allMessages);
	}

	private void assertMessageNotInLogLine(String... expected) {

		String allMessages = log.toString();
		String[] logLines = allMessages.split("\n");
		for (String line : logLines) {
			if (StringUtilities.containsAllIgnoreCase(line, expected)) {
				fail("The folllowing source text unexpectedly has a line containing:\n" +
					Arrays.toString(expected) + "\n\nActual Text:\n" + allMessages);
			}
		}
	}

	private void analyze() {
		tx(program, () -> analyzer.added(program, program.getMemory(), TaskMonitor.DUMMY, log));
	}

	private void assertNotDemangled(Address addr, String name) {

		SymbolTable st = program.getSymbolTable();
		Symbol[] symbols = st.getSymbols(addr);
		for (Symbol s : symbols) {
			if (s.getName().equals(name)) {
				fail("Symbol should not have been demangled '" + name + "'");
			}
		}
	}

	private void assertDemangled(Address addr, String name) {

		SymbolTable st = program.getSymbolTable();
		Symbol[] symbols = st.getSymbols(addr);
		for (Symbol s : symbols) {
			if (s.getName().equals(name)) {
				return;
			}
		}

		fail("Unable to find demangled symbol '" + name + "'");
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

	private void setOption(String optionName, String value) {

		String fullOptionName = analyzer.getName() + Options.DELIMITER_STRING + optionName;
		Options options = program.getOptions("Analyzers");

		for (String name : options.getOptionNames()) {
			if (name.equals(fullOptionName)) {
				tx(program, () -> options.setString(optionName, value));

				// we must call this manually, since we are not using a tool
				analyzer.optionsChanged(options, program);
				return;
			}
		}

		fail("Could not find option '" + optionName + "'");
	}

	private void createSymbol(Address addr, String mangled) {
		AddLabelCmd cmd = new AddLabelCmd(addr, mangled, SourceType.ANALYSIS);
		applyCmd(program, cmd);
	}

	private Address addr(String addr) {
		return program.getAddressFactory().getAddress(addr);
	}

	private void registerOptions() {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		Options analyzerOptions = options.getOptions(analyzer.getName());
		analyzer.registerOptions(analyzerOptions, program);
	}
}
