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
package ghidra.app.plugin.core.codebrowser;

import org.junit.After;
import org.junit.Before;

import docking.action.DockingActionIf;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.GThreadedTablePanel;
import generic.test.TestUtils;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.plugin.core.table.TableServicePlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.test.*;

public class AbstractCodeBrowserNavigationTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private DockingActionIf prev;
	private DockingActionIf clearHistory;
	private DockingActionIf nextFunction;
	private DockingActionIf prevFunction;

	protected ToyProgramBuilder builder;
	protected Program program;
	protected CodeBrowserPlugin cb;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		program = buildProgram();
		tool = env.launchDefaultTool(program);

		addrFactory = program.getAddressFactory();

		NextPrevAddressPlugin np = env.getPlugin(NextPrevAddressPlugin.class);
		prev = getAction(np, "Previous Location in History");
		clearHistory = getAction(np, "Clear History Buffer");
		cb = env.getPlugin(CodeBrowserPlugin.class);

		nextFunction = getAction(cb, "Go To Next Function");
		prevFunction = getAction(cb, "Go To Previous Function");
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	protected PluginTool getTool() {
		return tool;
	}

	protected void loadProgram() throws Exception {
		program = buildProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		addrFactory = program.getAddressFactory();
	}

	private Program buildProgram() throws Exception {
		builder = new ToyProgramBuilder("Test", true, this);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);
		builder.createMemory(".bound_import.table", "0xf0000428", 0xa8);
		builder.createMemory(".debug_data", "0xf0001300", 0x1c);
		builder.setBytes("0x1002000", "01 00 30 00");
		builder.applyDataType("0x1002000", DWordDataType.dataType, 1);
		builder.setBytes("0x1002010", "11 00 00 00");
		builder.applyDataType("0x1002010", DWordDataType.dataType, 1);

		builder.createExternalFunction("0x1001888", "ADVAPI32.dll", "IsTextUnicode");

		builder.applyDataType("0x1001000", PointerDataType.dataType, 1);
		builder.createExternalReference("0x1001000", "ADVAPI32.dll", "IsTextUnicode", 0); // linkage location
		builder.createExternalReference("0x1001020", "ADVAPI32.dll", "IsTextUnicode", 0); // without pointer

		builder.addBytesBranch("1004000", "1004010");
		builder.addBytesBranch("1004030", "1004010");
		builder.addBytesBranch("1004040", "1004010");
		builder.disassemble("1004000", 1);
		builder.disassemble("1004030", 1);
		builder.disassemble("1004040", 1);

		builder.addBytesFallthrough("0x1006000");
		builder.addBytesMoveImmediate("1006002", (byte) 0x12);
		builder.addBytesLoad("1006004", 0, 1);
		builder.addBytesReturn("1006006");
		builder.disassemble("1006000", 8);

		Function func = builder.createFunction("0x1006000");
		builder.createRegisterReference("0x1006002", RefType.WRITE, "r0", SourceType.USER_DEFINED,
			0);

		// note: as of this writing, analysis was placing a reference from this address.  The test
		//       is also placing a reference there.  Drop the analysis ref and keep the test ref.
		ProgramDB p = builder.getProgram();
		ReferenceManager rm = p.getReferenceManager();
		Reference[] refs = rm.getReferencesFrom(builder.addr("0x1006004"));
		for (Reference reference : refs) {
			builder.deleteReference(reference);
		}

		builder.createMemoryReference("0x1006004", "0x1005012", RefType.WRITE,
			SourceType.USER_DEFINED, 1);
		builder.addFunctionVariable(func, new LocalVariableImpl("foo", 2, ByteDataType.dataType,
			builder.getRegister("r0"), builder.getProgram()));

		builder.createFunction("0x1006100");
		builder.createFunction("0x1006200");

		builder.addBytesMoveImmediate("0x1004050", (byte) 0xb5);
		builder.createMemoryReference("0x1004050", "0x1008010", RefType.DATA,
			SourceType.USER_DEFINED, 0);
		builder.createMemoryReference("0x1004050", "0x1008020", RefType.DATA,
			SourceType.USER_DEFINED, 0);
		builder.createMemoryReference("0x1004050", "0x1008030", RefType.DATA,
			SourceType.USER_DEFINED, 0);
		builder.createMemoryReference("0x1004050", "0x1008040", RefType.DATA,
			SourceType.USER_DEFINED, 0);
		builder.createMemoryReference("0x1004050", "0x1008050", RefType.DATA,
			SourceType.USER_DEFINED, 0);
		builder.createMemoryReference("0x1004050", "0x1008060", RefType.DATA,
			SourceType.USER_DEFINED, 0);
		builder.createMemoryReference("0x1004050", "0x1008070", RefType.DATA,
			SourceType.USER_DEFINED, 0);
		builder.createMemoryReference("0x1004050", "0x1008080", RefType.DATA,
			SourceType.USER_DEFINED, 0);
		builder.createMemoryReference("0x1004050", "0x1008090", RefType.DATA,
			SourceType.USER_DEFINED, 0);

		return builder.getProgram();
	}

	protected Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	protected void myPerformAction(DockingActionIf a) {
		performAction(a, cb.getProvider(), true);
		cb.updateNow();
	}

	protected void nextFunction() {
		performAction(nextFunction, cb.getProvider(), true);
	}

	protected void prevFunction() {
		performAction(prevFunction, cb.getProvider(), true);
	}

	protected void clearHistory() {
		performAction(clearHistory, cb.getProvider(), true);
	}

	protected boolean isPreviousInHistoryEnabled() {
		return isEnabled(prev);
	}

	protected void goTo(ProgramLocation loc) {
		cb.goTo(loc);
		waitForSwing();
	}

	protected TableComponentProvider<?>[] getProviders() {
		TableServicePlugin plugin = getPlugin(getTool(), TableServicePlugin.class);
		return plugin.getManagedComponents();
	}

	protected GTable waitForResults() throws Exception {
		waitForSwing(); // Without waiting here the model may not be busy yet.
		int i = 0;
		while (i++ < 50) {
			TableComponentProvider<?>[] providers = getProviders();
			if (providers.length > 0) {
				GThreadedTablePanel<?> panel =
					(GThreadedTablePanel<?>) TestUtils.getInstanceField("threadedPanel",
						providers[0]);
				GTable table = panel.getTable();
				while (panel.isBusy()) {
					Thread.sleep(50);
				}
				waitForSwing(); // flush any residual swing processing
				return table;
			}
			Thread.sleep(50);
		}
		throw new Exception("Unable to get threaded table model");
	}
}
