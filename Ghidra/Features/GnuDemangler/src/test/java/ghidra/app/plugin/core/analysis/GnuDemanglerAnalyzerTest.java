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
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.Msg;
import ghidra.util.exception.RollbackException;
import ghidra.util.task.TaskMonitor;

public class GnuDemanglerAnalyzerTest extends AbstractGhidraHeadlessIntegrationTest {

	private GnuDemanglerAnalyzer analyzer = new GnuDemanglerAnalyzer();
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {

		ProgramBuilder builder = new ToyProgramBuilder("test", true);
		builder.createMemory(".text", "0x0100", 0x100);
		program = builder.getProgram();
		registerOptions();
	}

	@Test
	public void testDeprectedDemangledString() throws Exception {

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

		MessageLog log = new MessageLog();
		analyzer.added(program, program.getMemory(), TaskMonitor.DUMMY, log);
	}

	private void setOption(String optionNameUseDeprecatedDemangler, boolean b) {

		Options options = program.getOptions("Analyzers");

		for (String name : options.getOptionNames()) {

			if (name.contains("Demangler GNU")) {
				Msg.out("found it: " + name);
			}
			else {
				Msg.out("no it: " + name);
			}
		}
	}

	private void createSymbol(Address addr, String mangled) {

		AddLabelCmd cmd = new AddLabelCmd(addr, mangled, SourceType.ANALYSIS);
		int txId = program.startTransaction(cmd.getName());
		boolean commit = true;
		try {
			boolean status = cmd.applyTo(program);
			program.flushEvents();

			if (!status) {
				fail("Could not apply command: " + cmd.getStatusMsg());
			}
		}
		catch (RollbackException e) {
			commit = false;
			throw e;
		}
		finally {
			program.endTransaction(txId, commit);
		}
	}

	@Test
	public void testDeprectedDemangledString_WithArguments_Valid() {

		fail();
	}

	@Test
	public void testDeprectedDemangledString_WithArguments_Invalid() {

		fail();
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
