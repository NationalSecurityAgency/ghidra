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
package docking.widgets.table;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.util.query.ProgramLocationPreviewTableModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.test.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.TaskMonitor;

public class GhidraTableTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program1;
	private ProgramDB program2;
	private TestEnv env;

	private GhidraTable table;
	private ProgramLocationPreviewTableModel model;

	@Before
	public void setUp() throws Exception {

		ClassicSampleX86ProgramBuilder x86Builder = new ClassicSampleX86ProgramBuilder();
		program1 = x86Builder.getProgram();
		program2 = buildToyProgram();

		env = new TestEnv();
		PluginTool tool = env.launchDefaultTool();

		env.open(program1);
		env.open(program2);

		model = createModel(tool);

		table = new GhidraTable(model);
		table.installNavigation(tool);

		waitForTableModel(model);
	}

	private ProgramLocationPreviewTableModel createModel(PluginTool tool) {
		return runSwing(() -> {
			return new ProgramLocationPreviewTableModel("TestModel", tool, program1,
				TaskMonitor.DUMMY) {

				@Override
				protected void doLoad(Accumulator<ProgramLocation> accumulator, TaskMonitor monitor)
						throws CancelledException {

					accumulator.add(location(program1, "0x01002cf5")); // ghidra
					accumulator.add(location(program1, "0x010048a3")); // doStuff

					accumulator.add(location(program2, "0x1001400")); // bob
					accumulator.add(location(program2, "0x1001100")); // main
				}

			};
		});
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testMultiProgramNavigation() throws Exception {

		/*
		 	Test that a table model with program locations from different programs will correctly
		 	navigate the listing.
		 */

		int row = getRow(program1, "0x01002cf5"); // ghidra
		navigate(row);
		assertActiveProgram(program1);
		assertLocation(program1, "0x01002cf5");

		row = getRow(program2, "0x1001400"); // bob
		navigate(row);
		assertActiveProgram(program2);
		assertLocation(program2, "0x1001400");

		row = getRow(program1, "0x010048a3"); // doStuff
		navigate(row);
		assertActiveProgram(program1);
		assertLocation(program1, "0x010048a3");

		row = getRow(program2, "0x1001100"); // main
		navigate(row);
		assertActiveProgram(program2);
		assertLocation(program2, "0x1001100");
	}

	@Test
	public void testMultiProgramNavigation_ListingAsNavigatable() throws Exception {

		/*
		 	Test that a table model with program locations from different programs will correctly
		 	navigate the listing.
		 */

		runSwing(() -> {

			CodeBrowserPlugin cb = env.getPlugin(CodeBrowserPlugin.class);
			CodeViewerProvider provider = cb.getProvider();
			table.installNavigation(env.getTool(), provider);

		});

		int row = getRow(program1, "0x01002cf5"); // ghidra
		navigate(row);
		assertActiveProgram(program1);
		assertLocation(program1, "0x01002cf5");

		row = getRow(program2, "0x1001400"); // bob
		navigate(row);
		assertActiveProgram(program2);
		assertLocation(program2, "0x1001400");

		row = getRow(program1, "0x010048a3"); // doStuff
		navigate(row);
		assertActiveProgram(program1);
		assertLocation(program1, "0x010048a3");

		row = getRow(program2, "0x1001100"); // main
		navigate(row);
		assertActiveProgram(program2);
		assertLocation(program2, "0x1001100");
	}

	private void assertActiveProgram(Program expectedProgram) {
		ProgramManagerPlugin pmp = env.getPlugin(ProgramManagerPlugin.class);
		Program currentProgram = pmp.getCurrentProgram();
		assertEquals(expectedProgram, currentProgram);
	}

	private int getRow(Program p, String addr) {
		ProgramLocation loc = location(p, addr);
		return runSwing(() -> model.getRowIndex(loc));
	}

	private ProgramDB buildToyProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder();

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createEntryPoint("0x1001100", "main");
		builder.addBytesNOP("0x1001100", 4);
		builder.disassemble("0x1001100", 4);
		builder.createFunction("0x1001100");

		builder.addBytesNOP("0x1001110", 4);
		builder.disassemble("0x1001110", 4);

		builder.addBytesReturn("0x1001200");
		builder.disassemble("0x1001200", 4);

		builder.createMemoryCallReference("1001000", "1001200");

		builder.addBytesReturn("1001300");
		builder.disassemble("1001300", 4);
		builder.createFunction("1001300");

		builder.createLabel("1001400", "bob");
		builder.createComment("1001400", "my comment", CommentType.PLATE);

		builder.addBytesReturn("1001500");
		builder.disassemble("1001500", 4);
		builder.createFunction("1001500");

		return builder.getProgram();
	}

	private ProgramLocation location(Program p, String addrString) {
		Address addr = addr(p, addrString);
		return new ProgramLocation(p, addr);
	}

	private void navigate(int row) {

		runSwing(() -> {
			table.navigate(row, 0);
		});

		waitForTasks();
	}

	private Address addr(Program p, String s) {
		AddressFactory af = p.getAddressFactory();
		return af.getAddress(s);
	}

	private void assertLocation(Program p, String addrString) {

		Address expectedAddr = addr(p, addrString);

		CodeBrowserPlugin cb = env.getPlugin(CodeBrowserPlugin.class);
		ProgramLocation loc = cb.getCurrentLocation();
		Address actualAddr = loc.getAddress();
		assertEquals(expectedAddr, actualAddr);
	}

}
