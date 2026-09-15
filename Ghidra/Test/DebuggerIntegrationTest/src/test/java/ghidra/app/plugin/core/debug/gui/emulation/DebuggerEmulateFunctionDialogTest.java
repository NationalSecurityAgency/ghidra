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
package ghidra.app.plugin.core.debug.gui.emulation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeFalse;

import java.lang.annotation.*;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

import javax.swing.JDialog;
import javax.swing.JTextField;
import javax.swing.tree.TreePath;

import org.hamcrest.Matchers;
import org.junit.*;

import db.Transaction;
import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.table.EnumeratedColumnTableModel;
import generic.Unique;
import generic.test.ConcurrentTestExceptionHandler;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.util.DataTypeChooserDialog;
import ghidra.app.plugin.core.datamgr.util.DataTypeChooserDialogTestHelper;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerIntegrationTest;
import ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointMarkerPlugin;
import ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsPlugin;
import ghidra.app.plugin.core.debug.gui.emulation.FunctionEmulationHarness.ReturnAddressInfo;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersPlugin;
import ghidra.app.plugin.core.debug.gui.time.DebuggerTimePlugin;
import ghidra.app.plugin.core.debug.service.breakpoint.ProgramBreakpoint;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.app.plugin.core.script.GhidraScriptMgrPlugin;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.util.task.TaskMonitorComponent;
import utility.function.ExceptionalCallback;

public class DebuggerEmulateFunctionDialogTest extends AbstractGhidraHeadedDebuggerIntegrationTest {
	final static List<String> DEFAULT_ASM = List.of(
		"load r10, [r12]",
		"imm r9, #8",
		"add r12, r9",
		"load r12, [r12]",
		"add r12, r10",
		"add r12, r11",
		"ret");

	PcodeArithmetic<byte[]> ba;
	Function function;
	DataType dtLongLong;
	Pointer dtStructPtr;
	DebuggerEmulateFunctionDialog dialog;
	Address addressOfLoad; // Address of *last* load instruction
	SleighLanguage language;
	DataTypeManager dtm;

	@Target(ElementType.METHOD)
	@Retention(RetentionPolicy.RUNTIME)
	@interface AltAsm {
		String[] value();
	}

	@SuppressWarnings("unchecked")
	<T extends DataType> T resolve(T dt) {
		try (Transaction tx = program.openTransaction("Resolved %s".formatted(dt))) {
			DataTypeConflictHandler handler = DataTypeConflictHandler.DEFAULT_HANDLER;
			return (T) dtm.resolve(dt, handler);
		}
	}

	String[] getAsm() throws Exception {
		Method method = null;
		try {
			method = getClass().getMethod(name.getMethodName());
		}
		catch (NoSuchMethodException e) {
			return DEFAULT_ASM.toArray(String[]::new);
		}
		AltAsm annotation = method.getAnnotation(AltAsm.class);
		if (annotation == null) {
			return DEFAULT_ASM.toArray(String[]::new);
		}
		return annotation.value();
	}

	@Before
	public void setupEmulateFunctionTest() throws Exception {
		createProgram();
		language = (SleighLanguage) program.getLanguage();
		dtm = program.getDataTypeManager();
		intoProject(program);
		ba = BytesPcodeArithmetic.forLanguage(program.getLanguage());
		try (Transaction tx = program.openTransaction("Create function")) {
			Address entry = addr(program, 0x00400000);

			program.getMemory()
					.createInitializedBlock(".text", entry, 0x1000, (byte) 0, monitor, false);

			Assembler asm = Assemblers.getAssembler(program);
			AddressSet body = new AddressSet();
			for (Instruction i : asm.assemble(entry, getAsm())) {
				body.add(new AddressRangeImpl(i.getMinAddress(), i.getMaxAddress()));
				if ("load".equals(i.getMnemonicString())) {
					addressOfLoad = i.getAddress();
				}
			}

			function = program.getFunctionManager()
					.createFunction("main", entry, body, SourceType.IMPORTED);

			dtLongLong = resolve(LongLongDataType.dataType);

			Structure st = new StructureDataType("myStruct", 0, dtm);
			st.add(dtLongLong, "first", "");
			st.add(dtLongLong, "second", "");
			dtStructPtr = resolve(new PointerDataType(st));

			Variable returnVar = new ReturnParameterImpl(dtLongLong, program);
			Variable param1 = new ParameterImpl("param1", dtStructPtr, program);
			Variable param2 = new ParameterImpl("param2", dtLongLong, program);

			function.updateFunction("default", returnVar, List.of(param1, param2),
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false, SourceType.ANALYSIS);
		}

		programManager.openProgram(program);

		dialog = runSwing(() -> new DebuggerEmulateFunctionDialog(tool, function));

		runSwing(() -> tool.showDialog(dialog));
	}

	@After
	public void tearDownEmulateFunctionTest() {
		runSwing(() -> dialog.close());
	}

	//@Test
	public void testManual() throws Exception {
		assumeFalse(BATCH_MODE);
		ConcurrentTestExceptionHandler.disable();

		addPlugin(tool, DataTypeManagerPlugin.class);
		addPlugin(tool, CodeBrowserPlugin.class);
		addPlugin(tool, FunctionPlugin.class);
		addPlugin(tool, DebuggerListingPlugin.class);
		addPlugin(tool, DebuggerTimePlugin.class);
		addPlugin(tool, DebuggerRegistersPlugin.class);
		addPlugin(tool, DebuggerBreakpointsPlugin.class);
		addPlugin(tool, DebuggerBreakpointMarkerPlugin.class);
		addPlugin(tool, GhidraScriptMgrPlugin.class);
		waitForSwing();

		while (runSwing(() -> dialog.isShowing())) {
			Thread.sleep(1000);
		}
	}

	record NameType(String name, DataType type) implements Comparable<NameType> {
		public static final Comparator<NameType> NATURAL_ORDER =
			Comparator.comparing(NameType::name);

		static NameType extract(VarRow row) {
			return new NameType(row.getName(), row.getType());
		}

		static List<NameType> extract(EnumeratedColumnTableModel<? extends VarRow> model) {
			return model.getModelData().stream().map(NameType::extract).sorted().toList();
		}

		@Override
		public int compareTo(NameType o) {
			return NATURAL_ORDER.compare(this, o);
		}
	}

	InputRow findInput(String name) {
		return runSwing(() -> dialog.findRow(dialog.inputsTableModel, name)).orElseThrow();
	}

	OutputRow findOutput(String name) {
		return runSwing(() -> dialog.findRow(dialog.outputsTableModel, name)).orElseThrow();
	}

	void performInputAction(String name, boolean wait) {
		ActionContext ctx = runSwing(() -> dialog.inputActions.getActionContext(null));
		performAction(dialog.inputActions.byName(name), ctx, wait);
	}

	void performOutputAction(String name, boolean wait) {
		ActionContext ctx = runSwing(() -> dialog.outputActions.getActionContext(null));
		performAction(dialog.outputActions.byName(name), ctx, wait);
	}

	@Test
	public void testRetInRegister() throws Exception {
		try (FunctionEmulationHarness harness =
			FunctionEmulationHarness.start(tool, function, monitor)) {
			ReturnAddressInfo retInfo = harness.locateReturnAddress();
			Register lr = harness.language.getRegister("lr");
			assertEquals(lr.getAddress(), retInfo.location());
			assertEquals(lr.getAddress(), retInfo.computePhysicalLocation(harness.initEval,
				harness.program.getCompilerSpec()));
		}
	}

	@Test
	@AltAsm({
		"pop lr",
		"ret" })
	public void testRetOnStack() throws Exception {
		try (FunctionEmulationHarness harness =
			FunctionEmulationHarness.start(tool, function, monitor)) {
			ReturnAddressInfo retInfo = harness.locateReturnAddress();
			AddressSpace stack = harness.program.getAddressFactory().getStackSpace();
			AddressSpace data = harness.language.getDefaultDataSpace();
			assertEquals(stack.getAddress(8), retInfo.location());
			assertEquals(data.getAddress(0x00005008), retInfo
					.computePhysicalLocation(harness.initEval, harness.program.getCompilerSpec()));
		}
	}

	@Test
	public void testDefaultVars() throws Exception {
		assertEquals(
			List.of(
				new NameType("param1", dtStructPtr),
				new NameType("param2", dtLongLong)),
			NameType.extract(dialog.inputsTableModel));
		assertEquals(
			List.of(
				new NameType("<RETURN>", dtLongLong)),
			NameType.extract(dialog.outputsTableModel));
	}

	@Test
	public void testRefreshParameters() throws Exception {
		InputRow param1 = findInput("param1");
		assertEquals(dtStructPtr, param1.getType());

		try (Transaction tx = program.openTransaction("Modify param1")) {
			Parameter p1 = function.getParameter(0);
			assertEquals("param1", p1.getName());
			p1.setDataType(dtLongLong, SourceType.USER_DEFINED);
		}
		waitForDomainObject(program);
		performInputAction("Refresh Parameter Inputs", true);

		param1 = findInput("param1");
		assertEquals(dtLongLong, param1.getType());
	}

	@Test
	public void testRefreshReturn() throws Exception {
		OutputRow ret = findOutput("<RETURN>");
		assertEquals(dtLongLong, ret.getType());

		try (Transaction tx = program.openTransaction("Modify return")) {
			function.getReturn().setDataType(dtStructPtr, SourceType.USER_DEFINED);
		}
		waitForDomainObject(program);
		performOutputAction("Refresh Return Outputs", true);

		ret = findOutput("<RETURN>");
		assertEquals(dtStructPtr, ret.getType());
	}

	<T extends Throwable> void expecting(Class<?> cls, ExceptionalCallback<T> cb) throws T {
		try {
			cb.call();
			fail("Did not get expected exception %s".formatted(cls.getSimpleName()));
		}
		catch (Throwable e) {
			if (cls.isInstance(e)) {
				return;
			}
			throw e;
		}
	}

	static final String RETURN = "<RETURN>";

	@Test
	public void testRefreshVoidReturn() throws Exception {
		findOutput(RETURN);

		try (Transaction tx = program.openTransaction("Modify return")) {
			function.getReturn().setDataType(VoidDataType.dataType, SourceType.USER_DEFINED);
		}
		waitForDomainObject(program);
		performOutputAction("Refresh Return Outputs", true);

		expecting(NoSuchElementException.class, () -> {
			findOutput(RETURN);
		});
	}

	TreePath path(String... path) {
		return new TreePath(path);
	}

	@Test
	public void testAddVararg() throws Exception {
		addPlugin(tool, DataTypeManagerPlugin.class);

		DockingActionIf actionAddVararg = dialog.inputActions.byName("Add Vararg Input");
		assertFalse(actionAddVararg.isEnabled());

		try (Transaction tx = program.openTransaction("Enable varargs")) {
			function.setVarArgs(true);
		}
		waitForDomainObject(program);

		assertTrue(actionAddVararg.isEnabled());
		performInputAction("Add Vararg Input", false);
		DataTypeChooserDialog typeDialog = waitForDialogComponent(DataTypeChooserDialog.class);
		waitForTasks();

		typeDialog.setSelectedPath(path("Data Types", "BuiltInTypes", "float"));
		waitForTasks();
		DataTypeChooserDialogTestHelper.clickOk(typeDialog);

		InputRow input = findInput("Vararg 3");
		assertEquals(resolve(FloatDataType.dataType), input.getType());
	}

	@Test
	public void testExpandStructPtr() throws Exception {
		InputRow param1 = findInput("param1");
		runSwing(() -> dialog.inputsFilterPanel.setSelectedItem(param1));
		performInputAction("Allocate and Add Pointer Inputs", true);

		InputRow param1First = findInput("(param1)->first");
		assertEquals(dtLongLong, param1First.getType());
		InputRow param1Second = findInput("(param1)->second");
		assertEquals(dtLongLong, param1Second.getType());
	}

	@Test
	public void testExpandSimplePtr() throws Exception {
		InputRow param1 = findInput("param1");
		DataType dtLongLongPtr = resolve(new PointerDataType(dtLongLong));
		param1.setType(dtLongLongPtr);
		runSwing(() -> dialog.inputsFilterPanel.setSelectedItem(param1));
		performInputAction("Allocate and Add Pointer Inputs", true);

		InputRow param1Deref = findInput("*(param1)");
		assertEquals(dtLongLong, param1Deref.getType());
	}

	void placeInject(Address address, String inject) {
		try (Transaction tx = program.openTransaction("Place inject")) {
			Bookmark bm = program.getBookmarkManager()
					.setBookmark(address, LogicalBreakpoint.ENABLED_BOOKMARK_TYPE, "x;1", "");
			ProgramBreakpoint brk = ProgramBreakpoint.fromBookmark(program, bm);
			brk.setEmuSleigh(inject);
		}
		waitForDomainObject(program);
	}

	@Test
	public void testFullUse() throws Exception {
		InputRow param1 = findInput("param1");
		runSwing(() -> dialog.inputsFilterPanel.setSelectedItem(param1));
		performInputAction("Allocate and Add Pointer Inputs", true);

		InputRow param1First = findInput("(param1)->first");
		param1First.setValue(ba.fromConst(6, param1First.length));
		InputRow param1Second = findInput("(param1)->second");
		param1Second.setRepr("7h");
		InputRow param2 = findInput("param2");
		param2.setRepr("8h");

		placeInject(addressOfLoad, """
				emu_probe(r12);
				emu_exec_decoded();
				""");

		runSwing(() -> dialog.okCallback());
		waitForTasks();

		OutputRow ret = findOutput("<RETURN>");
		assertEquals("15h", ret.getRepr());
		OutputRow probe = findOutput("Probe 1");
		assertEquals(0x7beef008L, ba.toLong(probe.value, Purpose.INSPECT));
	}

	@Test
	public void testAddCustom() throws Exception {
		performInputAction("Add Custom Input", false);
		JDialog exprDialog = waitForJDialog("Add Custom Input");
		JTextField exprField = findComponent(exprDialog, JTextField.class);
		exprField.setText("r10");
		runSwing(() -> findButtonByText(exprDialog, "OK").doClick());

		assertNotNull(findInput("Custom 1"));
	}

	@Test
	public void testConflictingInputs() throws Exception {
		InputRow custom1 =
			new InputRow(language, "Custom 1", VarStorage.fromExpression(language, "r12"), null);
		dialog.inputsTableModel.add(custom1);
		InputRow param1 = findInput("param1");
		assertEquals(custom1.storage, param1.storage);

		custom1.setValueStr("0x1");
		param1.setValueStr("0x7");

		runSwing(() -> dialog.okCallback());
		waitForTasks();
		String status = runSwing(() -> dialog.getStatusText());
		assertThat(status,
			Matchers.either(Matchers.equalTo("Input r12 conflicts: 0x1 != 0x7"))
					.or(Matchers.equalTo("Input r12 conflicts: 0x7 != 0x1")));
	}

	@Test
	public void testRemovedDependencyNotApplied() throws Exception {
		InputRow param1 = findInput("param1");
		runSwing(() -> dialog.inputsFilterPanel.setSelectedItem(param1));
		performInputAction("Allocate and Add Pointer Inputs", true);

		InputRow param1First = findInput("(param1)->first");
		param1First.setValue(ba.fromConst(6, param1First.length));
		InputRow param1Second = findInput("(param1)->second");
		param1Second.setRepr("7h");
		InputRow param2 = findInput("param2");
		param2.setRepr("8h");

		// Not zeros. Should be alloced address
		assertFalse(Arrays.equals(new byte[param1.length], param1.getValue()));

		runSwing(() -> dialog.inputsFilterPanel.setSelectedItem(param1));
		performInputAction("Remove Input", true);

		runSwing(() -> dialog.okCallback());
		waitForTasks();

		tb = new ToyDBTraceBuilder(Unique.assertOne(traceManager.getOpenTraces()));
		// Should wind up at zero, because param1 is not be applied
		ByteBuffer buf = ByteBuffer.allocate(dtStructPtr.getDataType().getLength())
				.order(language.isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		tb.trace.getMemoryManager().getBytes(0, tb.addr(0), buf);
		buf.flip();
		assertEquals(6, buf.getLong());
		assertEquals(7, buf.getLong());
	}

	@Test
	public void testDependencyRefreshedStillAffectsDependents() throws Exception {
		InputRow param1 = findInput("param1");
		runSwing(() -> dialog.inputsFilterPanel.setSelectedItem(param1));
		performInputAction("Allocate and Add Pointer Inputs", true);

		InputRow param1First = findInput("(param1)->first");
		param1First.setValue(ba.fromConst(6, param1First.length));
		InputRow param1Second = findInput("(param1)->second");
		param1Second.setRepr("7h");
		InputRow param2 = findInput("param2");
		param2.setRepr("8h");

		runSwing(() -> dialog.inputsFilterPanel.setSelectedItem(param1));
		performInputAction("Remove Input", true);
		performInputAction("Refresh Parameter Inputs", true);
		InputRow param1a = findInput("param1");
		assertNotSame(param1, param1a);

		Address newAddr = program.getAddressFactory().getAddress("00600000");
		param1a.setValue(ba.fromConst(newAddr));

		runSwing(() -> dialog.okCallback());
		waitForTasks();

		tb = new ToyDBTraceBuilder(Unique.assertOne(traceManager.getOpenTraces()));
		// Should wind up at zero, because param1 is not be applied
		ByteBuffer buf = ByteBuffer.allocate(dtStructPtr.getDataType().getLength())
				.order(language.isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
		tb.trace.getMemoryManager().getBytes(0, newAddr, buf);
		buf.flip();
		assertEquals(6, buf.getLong());
		assertEquals(7, buf.getLong());
	}

	@Test
	public void testCancelLoop() throws Exception {
		placeInject(addressOfLoad, """
				goto 0x%s;
				""".formatted(function.getEntryPoint()));

		runSwing(() -> dialog.okCallback());

		TaskMonitorComponent monitor =
			waitForValue(() -> findComponent(dialog, TaskMonitorComponent.class));
		runSwing(() -> monitor.cancel());
		waitForTasks();
	}

	/**
	 * i.e., an expression is placed inside the probe vs. just a varnode
	 * 
	 * @throws Exception because
	 */
	@Test
	public void testProbeUnique() throws Exception {
		// Note: r12 should be 8 at this address
		placeInject(addressOfLoad, """
				emu_probe(r12 + 0x1234);
				emu_exec_decoded();
				""");

		runSwing(() -> dialog.okCallback());
		waitForTasks();

		OutputRow probe = findOutput("Probe 1");
		assertEquals("$Unique", probe.getStorage().toString());
		assertEquals(0x123c, ba.toLong(probe.value, Purpose.INSPECT));
	}
}
