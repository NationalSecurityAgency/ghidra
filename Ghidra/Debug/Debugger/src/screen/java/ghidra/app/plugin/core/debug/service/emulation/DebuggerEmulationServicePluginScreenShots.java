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
package ghidra.app.plugin.core.debug.service.emulation;

import java.io.IOException;
import java.util.List;

import org.junit.*;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.emulation.DebuggerEmulateFunctionDialog;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerEmulationServicePluginScreenShots extends GhidraScreenShotGenerator {
	private static final TaskMonitor MONITOR = new ConsoleTaskMonitor();

	private static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private static AddressSetView set(Program program, long min, long max) {
		return new AddressSet(addr(program, min), addr(program, max));
	}

	ProgramManager programManager;
	DebuggerEmulationServicePlugin emuService;
	Function function;
	Program progam;
	DataTypeManager dtm;

	DataType dtInt;
	DataType dtCharPtrPtr;
	DataType dtStructPtr;

	@Before
	public void setUpMine() throws Throwable {
		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		emuService = addPlugin(tool, DebuggerEmulationServicePlugin.class);
	}

	@After
	public void tearDownMine() {
		if (program != null) {
			program.release(this);
		}
	}

	// TODO: Propose this replace waitForProgram
	public static void waitForDomainObject(DomainObject object) {
		object.flushEvents();
		waitForSwing();
	}

	protected void intoProject(DomainObject obj) {
		waitForDomainObject(obj);
		DomainFolder rootFolder = tool.getProject().getProjectData().getRootFolder();
		waitForCondition(() -> {
			try {
				rootFolder.createFile(obj.getName(), obj, MONITOR);
				return true;
			}
			catch (InvalidNameException | CancelledException e) {
				throw new AssertionError(e);
			}
			catch (IOException e) {
				// Usually "object is busy". Try again.
				return false;
			}
		});
	}

	@SuppressWarnings("unchecked")
	<T extends DataType> T resolve(T dt) {
		try (Transaction tx = program.openTransaction("Resolved %s".formatted(dt))) {
			DataTypeConflictHandler handler = DataTypeConflictHandler.DEFAULT_HANDLER;
			return (T) dtm.resolve(dt, handler);
		}
	}

	@Test
	public void testCaptureDebuggerEmulateFunctionDialog() throws Throwable {
		program = createDefaultProgram("game", ToyProgramBuilder._X64, this);
		intoProject(program);
		dtm = program.getDataTypeManager();
		try (Transaction tx = program.openTransaction("Create Function")) {
			program.getMemory()
					.createInitializedBlock(".text", addr(program, 0x00400000), 0x10000, (byte) 0,
						MONITOR, false);
			function = program.getFunctionManager()
					.createFunction("parse_opts", addr(program, 0x00401000),
						set(program, 0x00401000, 0x00401100), SourceType.USER_DEFINED);

			dtInt = resolve(IntegerDataType.dataType);
			dtCharPtrPtr = resolve(new PointerDataType(new PointerDataType(CharDataType.dataType)));

			Structure st = new StructureDataType("Options", 0, dtm);
			st.add(dtInt, "width", "");
			st.add(dtInt, "height", "");
			dtStructPtr = resolve(new PointerDataType(st));

			Variable returnVar = new ReturnParameterImpl(dtStructPtr, program);
			Variable param1 = new ParameterImpl("argc", dtInt, program);
			Variable param2 = new ParameterImpl("argv", dtCharPtrPtr, program);

			function.updateFunction("default", returnVar, List.of(param1, param2),
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.ANALYSIS);
		}
		programManager.openProgram(program);
		goTo(tool, progam, function.getEntryPoint());
		performAction(emuService.actionEmulateFunction, false);

		DebuggerEmulateFunctionDialog dialog =
			waitForDialogComponent(DebuggerEmulateFunctionDialog.class);

		runSwing(() -> dialog.getComponent().requestFocus());
		captureDialog(dialog);
	}
}
