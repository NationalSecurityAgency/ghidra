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
package ghidra.app.plugin.core.debug.gui.copying;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;

import javax.swing.JCheckBox;

import org.junit.Test;

import db.Transaction;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.AllCopiers;
import ghidra.app.util.viewer.listingpanel.PropertyBasedBackgroundColorModel;
import ghidra.program.database.IntRangeMap;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.trace.database.breakpoint.DBTraceBreakpointManager;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.program.DBTraceVariableSnapProgramView;
import ghidra.trace.database.symbol.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.util.task.TaskMonitor;

public class DebuggerCopyPlanTests extends AbstractGhidraHeadedDebuggerGUITest {
	public static class TestDynamicDataType extends CountedDynamicDataType {
		public static final TestDynamicDataType dataType = new TestDynamicDataType();

		public TestDynamicDataType() {
			super("test_dyn", "A test dynamic type", ShortDataType.dataType, ByteDataType.dataType,
				0, 2, 0xffff);
		}
	}

	@Test
	public void testBytes() throws Exception {
		createTrace();
		createProgram(getSLEIGH_X86_64_LANGUAGE());
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		assertTrue(AllCopiers.BYTES.isAvailable(view, program));

		Random r = new Random();
		byte src[] = new byte[0x10000];
		r.nextBytes(src);
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.createRegion(".text", 0, tb.range(0x55550000, 0x5555ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			memory.putBytes(0, tb.addr(0x55550000), ByteBuffer.wrap(src));
		}

		Address paddr = tb.addr(stSpace, 0x00400000);
		assertTrue(AllCopiers.BYTES.isRequiresInitializedMemory());
		try (Transaction tx = program.openTransaction("Copy")) {
			program.getMemory()
					.createInitializedBlock(".text", paddr, 0x10000, (byte) 0, TaskMonitor.DUMMY,
						false);
			AllCopiers.BYTES.copy(view, tb.range(0x55550000, 0x5555ffff), program, paddr,
				TaskMonitor.DUMMY);
		}

		byte dst[] = new byte[0x10000];
		program.getMemory().getBytes(paddr, dst);

		assertArrayEquals(src, dst);
	}

	@Test
	public void testState() throws Exception {
		createTrace();
		createProgram(getSLEIGH_X86_64_LANGUAGE());
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		assertTrue(AllCopiers.STATE.isAvailable(view, program));

		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.createRegion(".text", 0, tb.range(0x55550000, 0x5555ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			memory.putBytes(0, tb.addr(0x55550000), ByteBuffer.allocate(4096));
			memory.setState(0, tb.addr(0x55551000), TraceMemoryState.ERROR);
		}

		Address paddr = tb.addr(stSpace, 0x00400000);
		assertFalse(AllCopiers.STATE.isRequiresInitializedMemory());
		try (Transaction tx = program.openTransaction("Copy")) {
			program.getMemory()
					.createInitializedBlock(".text", paddr, 0x10000, (byte) 0, TaskMonitor.DUMMY,
						false);
			AllCopiers.STATE.copy(view, tb.range(0x55550000, 0x5555ffff), program, paddr,
				TaskMonitor.DUMMY);
		}

		IntRangeMap map =
			program.getIntRangeMap(PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
		AddressSet staleSet =
			map.getAddressSet(DebuggerResources.COLOR_BACKGROUND_STALE.getRGB());
		assertEquals(tb.set(tb.range(stSpace, 0x00401001, 0x0040ffff)), staleSet);
		AddressSet errorSet =
			map.getAddressSet(DebuggerResources.COLOR_BACKGROUND_ERROR.getRGB());
		assertEquals(tb.set(tb.range(stSpace, 0x00401000, 0x00401000)), errorSet);
	}

	@Test
	public void testInstructionsMismatched() throws Exception {
		createTrace();
		createProgram(getSLEIGH_X86_64_LANGUAGE());

		assertFalse(AllCopiers.INSTRUCTIONS.isAvailable(tb.trace.getProgramView(), program));
	}

	@Test
	public void testInstructionsDepBytes() throws Exception {
		DebuggerCopyPlan plan = new DebuggerCopyPlan();
		JCheckBox cbInstructions = plan.getCheckBox(AllCopiers.INSTRUCTIONS);
		JCheckBox cbBytes = plan.getCheckBox(AllCopiers.BYTES);
		assertFalse(cbInstructions.isSelected());
		assertFalse(cbBytes.isSelected());

		cbInstructions.doClick();
		assertTrue(cbInstructions.isSelected());
		assertTrue(cbBytes.isSelected());

		cbInstructions.doClick();
		assertFalse(cbInstructions.isSelected());
		assertTrue(cbBytes.isSelected());

		cbInstructions.doClick();
		assertTrue(cbInstructions.isSelected());
		assertTrue(cbBytes.isSelected());

		cbBytes.doClick();
		assertFalse(cbInstructions.isSelected());
		assertFalse(cbBytes.isSelected());

		cbBytes.doClick();
		assertFalse(cbInstructions.isSelected());
		assertTrue(cbBytes.isSelected());
	}

	@Test
	public void testInstructions() throws Exception {
		createTrace();
		createProgram();
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		assertTrue(AllCopiers.BYTES.isAvailable(view, program));
		assertTrue(AllCopiers.INSTRUCTIONS.isAvailable(view, program));

		AddressRange trng = tb.range(0x55550000, 0x5555ffff);
		Assembler asm = Assemblers.getAssembler(view);
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.createRegion(".text", 0, trng, TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			InstructionIterator iit = asm.assemble(tb.addr(0x55550000),
				"imm r0, #123",
				"imm r1, #234",
				"add r0, r1");
			assertTrue(iit.hasNext());
		}

		try (Transaction tx = program.openTransaction("Copy")) {
			Address paddr = tb.addr(stSpace, 0x00400000);
			program.getMemory()
					.createInitializedBlock(".text", paddr, 0x10000, (byte) 0, TaskMonitor.DUMMY,
						false);
			AllCopiers.BYTES.copy(view, trng, program, paddr, TaskMonitor.DUMMY);
			AllCopiers.INSTRUCTIONS.copy(view, trng, program, paddr, TaskMonitor.DUMMY);
		}

		List<Instruction> instructions = new ArrayList<>();
		program.getListing().getInstructions(true).forEachRemaining(instructions::add);

		assertEquals(3, instructions.size());
		Instruction ins;

		ins = instructions.get(0);
		assertEquals(tb.addr(stSpace, 0x00400000), ins.getAddress());
		assertEquals("imm r0,#0x7b", ins.toString());
		ins = instructions.get(1);
		assertEquals(tb.addr(stSpace, 0x00400002), ins.getAddress());
		assertEquals("imm r1,#0xea", ins.toString());
		ins = instructions.get(2);
		assertEquals(tb.addr(stSpace, 0x00400004), ins.getAddress());
		assertEquals("add r0,r1", ins.toString());
	}

	@Test
	public void testInstructionsWithDefaultContext() throws Exception {
		createTrace("x86:LE:64:default");
		createProgram(getSLEIGH_X86_64_LANGUAGE());
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		assertTrue(AllCopiers.BYTES.isAvailable(view, program));
		assertTrue(AllCopiers.INSTRUCTIONS.isAvailable(view, program));

		AddressRange trng = tb.range(0x55550000, 0x5555ffff);
		Assembler asm = Assemblers.getAssembler(view);
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.createRegion(".text", 0, trng, TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			InstructionIterator iit = asm.assemble(tb.addr(0x55550000),
				"MOV RAX, 1234",
				"MOV RCX, 2345",
				"ADD RAX, RCX");
			assertTrue(iit.hasNext());
		}

		try (Transaction tx = program.openTransaction("Copy")) {
			Address paddr = tb.addr(stSpace, 0x00400000);
			program.getMemory()
					.createInitializedBlock(".text", paddr, 0x10000, (byte) 0, TaskMonitor.DUMMY,
						false);
			AllCopiers.BYTES.copy(view, trng, program, paddr, TaskMonitor.DUMMY);
			AllCopiers.INSTRUCTIONS.copy(view, trng, program, paddr, TaskMonitor.DUMMY);
		}

		List<Instruction> instructions = new ArrayList<>();
		program.getListing().getInstructions(true).forEachRemaining(instructions::add);

		assertEquals(3, instructions.size());
		Instruction ins;

		ins = instructions.get(0);
		assertEquals(tb.addr(stSpace, 0x00400000), ins.getAddress());
		assertEquals("MOV RAX,0x4d2", ins.toString());
		ins = instructions.get(1);
		assertEquals(tb.addr(stSpace, 0x00400007), ins.getAddress());
		assertEquals("MOV RCX,0x929", ins.toString());
		ins = instructions.get(2);
		assertEquals(tb.addr(stSpace, 0x0040000e), ins.getAddress());
		assertEquals("ADD RAX,RCX", ins.toString());
	}

	@Test
	public void testInstructionsWithContext() throws Exception {
		createTrace("x86:LE:64:default");
		createProgram(getSLEIGH_X86_64_LANGUAGE());
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		assertTrue(AllCopiers.BYTES.isAvailable(view, program));
		assertTrue(AllCopiers.INSTRUCTIONS.isAvailable(view, program));

		AddressRange trng = tb.range(0x55550000, 0x5555ffff);
		// Assembler asm = Assemblers.getAssembler(view);

		Register contextReg = tb.language.getContextBaseRegister();
		Register longMode = tb.language.getRegister("longMode");
		RegisterValue rv = tb.trace.getRegisterContextManager()
				.getValueWithDefault(tb.host, contextReg, 0, tb.addr(0x55550000));
		rv = rv.assign(longMode, BigInteger.ZERO);
		Instruction checkCtx;
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.createRegion(".text", 0, trng, TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			tb.trace.getRegisterContextManager().setValue(tb.language, rv, Lifespan.nowOn(0), trng);

			// TODO: Once GP-1426 is resolved, use the assembler
			/*
			InstructionIterator iit = asm.assemble(tb.addr(0x55550000),
				"MOV EAX, 1234",
				"MOV ECX, 2345",
				"ADD EAX, ECX");
			checkCtx = iit.next();
			*/
			memory.putBytes(0, tb.addr(0x55550000), tb.buf(
				0xb8, 0xd2, 0x04, 0x00, 0x00, // MOV EAX,1234
				0xb9, 0x29, 0x09, 0x00, 0x00, // MOV ECX,2345
				0x01, 0xc8 // ADD EAX,ECX
			));
			Disassembler
					.getDisassembler(view, TaskMonitor.DUMMY, DisassemblerMessageListener.IGNORE)
					.disassemble(tb.addr(0x55550000), tb.set(tb.range(0x55550000, 0x5555000b)));
			checkCtx = tb.trace.getCodeManager().instructions().getAt(0, tb.addr(0x55550000));
		}
		// Sanity pre-check
		RegisterValue insCtx = checkCtx.getRegisterValue(contextReg);
		assertFalse(insCtx.equals(tb.trace.getRegisterContextManager()
				.getDefaultValue(tb.language, contextReg, checkCtx.getAddress())));

		try (Transaction tx = program.openTransaction("Copy")) {
			Address paddr = tb.addr(stSpace, 0x00400000);
			program.getMemory()
					.createInitializedBlock(".text", paddr, 0x10000, (byte) 0, TaskMonitor.DUMMY,
						false);
			AllCopiers.BYTES.copy(view, trng, program, paddr, TaskMonitor.DUMMY);
			AllCopiers.INSTRUCTIONS.copy(view, trng, program, paddr, TaskMonitor.DUMMY);
		}

		List<Instruction> instructions = new ArrayList<>();
		program.getListing().getInstructions(true).forEachRemaining(instructions::add);

		assertEquals(3, instructions.size());
		Instruction ins;

		ins = instructions.get(0);
		assertEquals(tb.addr(stSpace, 0x00400000), ins.getAddress());
		assertEquals("MOV EAX,0x4d2", ins.toString());
		ins = instructions.get(1);
		assertEquals(tb.addr(stSpace, 0x00400005), ins.getAddress());
		assertEquals("MOV ECX,0x929", ins.toString());
		ins = instructions.get(2);
		assertEquals(tb.addr(stSpace, 0x0040000a), ins.getAddress());
		assertEquals("ADD EAX,ECX", ins.toString());
	}

	@Test
	public void testDataMismatched() throws Exception {
		createTrace();
		createProgram(getSLEIGH_X86_64_LANGUAGE());

		assertFalse(AllCopiers.DATA.isAvailable(tb.trace.getProgramView(), program));
	}

	@Test
	public void testData() throws Exception {
		createTrace();
		createProgram();
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		assertTrue(AllCopiers.DATA.isAvailable(view, program));

		AddressRange trng = tb.range(0x55560000, 0x5556ffff);
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.createRegion(".data", 0, trng, TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
			tb.addData(0, tb.addr(0x55560000), ByteDataType.dataType, tb.buf(0x12));
			tb.addData(0, tb.addr(0x55560001), ShortDataType.dataType, tb.buf(0x12, 0x34));
			tb.addData(0, tb.addr(0x55560003), IntegerDataType.dataType,
				tb.buf(0x12, 0x34, 0x56, 0x78));
			tb.addData(0, tb.addr(0x55560007), LongLongDataType.dataType,
				tb.buf(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0));
			tb.addData(0, tb.addr(0x5556000f), TestDynamicDataType.dataType,
				tb.buf(0x00, 0x03, 0x00, 0x01, 0x02));
		}

		try (Transaction tx = program.openTransaction("Copy")) {
			Address paddr = tb.addr(stSpace, 0x00600000);
			program.getMemory()
					.createInitializedBlock(".data", paddr, 0x10000, (byte) 0, TaskMonitor.DUMMY,
						false);
			AllCopiers.DATA.copy(view, trng, program, paddr, TaskMonitor.DUMMY);
		}

		List<Data> data = new ArrayList<>();
		program.getListing().getDefinedData(true).forEachRemaining(data::add);

		// NB. Bytes were not copied. Dynamic omitted.
		assertEquals(4, data.size());
		Data dat;

		dat = data.get(0);
		assertEquals(tb.addr(stSpace, 0x00600000), dat.getAddress());
		assertEquals("db 0h", dat.toString());
		dat = data.get(1);
		assertEquals(tb.addr(stSpace, 0x00600001), dat.getAddress());
		assertEquals("short 0h", dat.toString());
		dat = data.get(2);
		assertEquals(tb.addr(stSpace, 0x00600003), dat.getAddress());
		assertEquals("int 0h", dat.toString());
		dat = data.get(3);
		assertEquals(tb.addr(stSpace, 0x00600007), dat.getAddress());
		assertEquals("longlong 0h", dat.toString());
	}

	@Test
	public void testDynamicDataMismatched() throws Exception {
		createTrace();
		createProgram(getSLEIGH_X86_64_LANGUAGE());

		assertFalse(AllCopiers.DYNAMIC_DATA.isAvailable(tb.trace.getProgramView(), program));
	}

	@Test
	public void testDynamicData() throws Exception {
		createTrace();
		createProgram();
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		assertTrue(AllCopiers.DYNAMIC_DATA.isAvailable(view, program));

		AddressRange trng = tb.range(0x55560000, 0x5556ffff);
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.createRegion(".data", 0, trng, TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
			tb.addData(0, tb.addr(0x55560000), ByteDataType.dataType, tb.buf(0x12));
			tb.addData(0, tb.addr(0x55560001), ShortDataType.dataType, tb.buf(0x12, 0x34));
			tb.addData(0, tb.addr(0x55560003), IntegerDataType.dataType,
				tb.buf(0x12, 0x34, 0x56, 0x78));
			tb.addData(0, tb.addr(0x55560007), LongLongDataType.dataType,
				tb.buf(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0));
			tb.addData(0, tb.addr(0x5556000f), TestDynamicDataType.dataType,
				tb.buf(0x00, 0x03, 0x00, 0x01, 0x02));
		}

		try (Transaction tx = program.openTransaction("Copy")) {
			Address paddr = tb.addr(stSpace, 0x00600000);
			program.getMemory()
					.createInitializedBlock(".data", paddr, 0x10000, (byte) 0, TaskMonitor.DUMMY,
						false);
			AllCopiers.BYTES.copy(view, trng, program, paddr, TaskMonitor.DUMMY);
			AllCopiers.DATA.copy(view, trng, program, paddr, TaskMonitor.DUMMY);
			AllCopiers.DYNAMIC_DATA.copy(view, trng, program, paddr, TaskMonitor.DUMMY);
		}

		List<Data> data = new ArrayList<>();
		program.getListing().getDefinedData(true).forEachRemaining(data::add);

		// NB. Bytes were not copied. Dynamic omitted.
		assertEquals(5, data.size());
		Data dat;
		Data cmp;

		dat = data.get(0);
		assertEquals(tb.addr(stSpace, 0x00600000), dat.getAddress());
		assertEquals("db 12h", dat.toString());
		dat = data.get(1);
		assertEquals(tb.addr(stSpace, 0x00600001), dat.getAddress());
		assertEquals("short 1234h", dat.toString());
		dat = data.get(2);
		assertEquals(tb.addr(stSpace, 0x00600003), dat.getAddress());
		assertEquals("int 12345678h", dat.toString());
		dat = data.get(3);
		assertEquals(tb.addr(stSpace, 0x00600007), dat.getAddress());
		assertEquals("longlong 123456789ABCDEF0h", dat.toString());

		dat = data.get(4);
		assertEquals(tb.addr(stSpace, 0x0060000f), dat.getAddress());
		assertEquals("test_dyn ", dat.toString());
		assertEquals(4, dat.getNumComponents()); // count + 3 elements
		cmp = dat.getComponent(0);
		assertEquals("short 3h", cmp.toString());
		cmp = dat.getComponent(1);
		assertEquals("db 0h", cmp.toString());
		cmp = dat.getComponent(2);
		assertEquals("db 1h", cmp.toString());
		cmp = dat.getComponent(3);
		assertEquals("db 2h", cmp.toString());
	}

	@Test
	public void testLabels() throws Exception {
		createTrace();
		createProgram(getSLEIGH_X86_64_LANGUAGE());
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		assertTrue(AllCopiers.LABELS.isAvailable(view, program));

		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.createRegion(".text", 0, tb.range(0x55550000, 0x5555ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			DBTraceNamespaceSymbol global = tb.trace.getSymbolManager().getGlobalNamespace();

			DBTraceLabelSymbolView labels = tb.trace.getSymbolManager().labels();
			labels.create(0, null, tb.addr(0x55550000), "test_label1", global, SourceType.IMPORTED);
			labels.create(0, null, tb.addr(0x55550005), "test_label2", global,
				SourceType.USER_DEFINED);
			DBTraceNamespaceSymbolView namespaces = tb.trace.getSymbolManager().namespaces();
			DBTraceNamespaceSymbol testNs = namespaces.add("test_ns", global, SourceType.ANALYSIS);
			DBTraceNamespaceSymbol testNsChild =
				namespaces.add("test_ns_child", testNs, SourceType.USER_DEFINED);
			labels.create(0, null, tb.addr(0x55550800), "test_label3", testNsChild,
				SourceType.ANALYSIS);
		}

		Address paddr = tb.addr(stSpace, 0x00400000);
		try (Transaction tx = program.openTransaction("Copy")) {
			program.getMemory()
					.createInitializedBlock(".text", paddr, 0x10000, (byte) 0, TaskMonitor.DUMMY,
						false);
			AllCopiers.LABELS.copy(view, tb.range(0x55550000, 0x5555ffff), program, paddr,
				TaskMonitor.DUMMY);
		}

		List<Symbol> symbols = new ArrayList<>();
		program.getSymbolTable().getSymbolIterator(true).forEachRemaining(symbols::add);

		assertEquals(3, symbols.size());
		Symbol sym;
		Namespace ns;

		sym = symbols.get(0);
		assertEquals("test_label1", sym.getName());
		assertEquals(tb.addr(stSpace, 0x00400000), sym.getAddress());
		assertEquals(SourceType.IMPORTED, sym.getSource());
		assertTrue(sym.isGlobal());
		sym = symbols.get(1);
		assertEquals("test_label2", sym.getName());
		assertEquals(tb.addr(stSpace, 0x00400005), sym.getAddress());
		assertEquals(SourceType.USER_DEFINED, sym.getSource());
		assertTrue(sym.isGlobal());

		sym = symbols.get(2);
		assertEquals("test_label3", sym.getName());
		assertEquals(tb.addr(stSpace, 0x00400800), sym.getAddress());
		assertEquals(SourceType.ANALYSIS, sym.getSource());
		assertFalse(sym.isGlobal());
		ns = sym.getParentNamespace();
		assertEquals("test_ns_child", ns.getName());
		assertEquals(SourceType.USER_DEFINED, ns.getSymbol().getSource());
		assertFalse(ns.isGlobal());
		ns = ns.getParentNamespace();
		assertEquals("test_ns", ns.getName());
		assertEquals(SourceType.ANALYSIS, ns.getSymbol().getSource());
		assertFalse(ns.isGlobal());
		ns = ns.getParentNamespace();
		assertTrue(ns.isGlobal());
	}

	@Test
	public void testBreakpoints() throws Exception {
		createTrace();
		createProgram(getSLEIGH_X86_64_LANGUAGE());
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		assertTrue(AllCopiers.BREAKPOINTS.isAvailable(view, program));

		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.createRegion(".text", 0, tb.range(0x55550000, 0x5555ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);

			DBTraceBreakpointManager breakpoints = tb.trace.getBreakpointManager();
			breakpoints.placeBreakpoint("[1]", 0, tb.addr(0x55550123), List.of(),
				Set.of(TraceBreakpointKind.SW_EXECUTE), true, "Test-1");
			breakpoints.placeBreakpoint("[2]", 0, tb.addr(0x55550321), List.of(),
				Set.of(TraceBreakpointKind.SW_EXECUTE), false, "Test-2");
		}

		Address paddr = tb.addr(stSpace, 0x55550000);
		try (Transaction tx = program.openTransaction("Init")) {
			program.getMemory()
					.createInitializedBlock(".text", paddr, 0x10000,
						(byte) 0, TaskMonitor.DUMMY, false);
			// Set up a collision. This is normal with relocations
			program.getBookmarkManager()
					.setBookmark(tb.addr(stSpace, 0x55550123), "BreakpointDisabled", "SW_EXECUTE;1",
						"");

			AllCopiers.BREAKPOINTS.copy(view, tb.range(0x55550000, 0x5555ffff), program, paddr,
				TaskMonitor.DUMMY);
		}

		List<Bookmark> bookmarks = new ArrayList<>();
		program.getBookmarkManager().getBookmarksIterator().forEachRemaining(bookmarks::add);

		assertEquals(2, bookmarks.size());
		Collections.sort(bookmarks, Comparator.comparing(Bookmark::getAddress));
		Bookmark bm;

		bm = bookmarks.get(0);
		assertEquals(tb.addr(stSpace, 0x55550123), bm.getAddress());
		assertEquals("BreakpointEnabled", bm.getTypeString());
		assertEquals("SW_EXECUTE;1", bm.getCategory());

		bm = bookmarks.get(1);
		assertEquals(tb.addr(stSpace, 0x55550321), bm.getAddress());
		assertEquals("BreakpointDisabled", bm.getTypeString());
		assertEquals("SW_EXECUTE;1", bm.getCategory());
	}

	@Test
	public void testBookmarks() throws Exception {
		createTrace();
		createProgram(getSLEIGH_X86_64_LANGUAGE());
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		assertTrue(AllCopiers.BOOKMARKS.isAvailable(view, program));

		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.createRegion(".text", 0, tb.range(0x55550000, 0x5555ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);

			BookmarkManager bookmarks = view.getBookmarkManager();
			bookmarks.defineType("TestType", DebuggerResources.ICON_DEBUGGER, Palette.BLUE, 1);
			bookmarks.setBookmark(tb.addr(0x55550123), "TestType", "TestCategory", "Test Comment");
		}

		Address paddr = tb.addr(stSpace, 0x55550000);
		try (Transaction tx = program.openTransaction("Init")) {
			program.getMemory()
					.createInitializedBlock(".text", paddr, 0x10000,
						(byte) 0, TaskMonitor.DUMMY, false);

			AllCopiers.BOOKMARKS.copy(view, tb.range(0x55550000, 0x5555ffff), program, paddr,
				TaskMonitor.DUMMY);
		}

		List<Bookmark> bookmarks = new ArrayList<>();
		program.getBookmarkManager().getBookmarksIterator().forEachRemaining(bookmarks::add);

		assertEquals(1, bookmarks.size());
		Bookmark bm;

		bm = bookmarks.get(0);
		assertEquals(tb.addr(stSpace, 0x55550123), bm.getAddress());
		BookmarkType type = program.getBookmarkManager().getBookmarkType("TestType");
		assertNotNull(type);
		assertEquals(type.getTypeString(), bm.getTypeString());
		assertEquals("TestCategory", bm.getCategory());
		assertEquals("Test Comment", bm.getComment());

		assertEquals(DebuggerResources.ICON_DEBUGGER, type.getIcon());
		assertEquals(Palette.BLUE, type.getMarkerColor());
		assertEquals(1, type.getMarkerPriority());
	}

	@Test
	public void testReferences() throws Exception {
		createTrace();
		createProgram(getSLEIGH_X86_64_LANGUAGE());
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		assertTrue(AllCopiers.REFERENCES.isAvailable(view, program));

		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.createRegion(".text", 0, tb.range(0x55550000, 0x5555ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			memory.createRegion(".data", 0, tb.range(0x55560000, 0x5556ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);

			ReferenceManager references = view.getReferenceManager();
			references.addMemoryReference(tb.addr(0x55550123),
				tb.addr(0x55550321), RefType.COMPUTED_CALL, SourceType.USER_DEFINED, -1);
			references.addMemoryReference(tb.addr(0x55550123),
				tb.addr(0x55560321), RefType.READ, SourceType.USER_DEFINED, -1);
			references.addMemoryReference(tb.addr(0x55560123),
				tb.addr(0x55550321), RefType.PARAM, SourceType.USER_DEFINED, -1);
			references.addMemoryReference(tb.addr(0x55560123),
				tb.addr(0x55560321), RefType.DATA, SourceType.USER_DEFINED, -1);
		}

		Address paddr = tb.addr(stSpace, 0x55550000);
		try (Transaction tx = program.openTransaction("Init")) {
			program.getMemory()
					.createInitializedBlock(".text", paddr, 0x10000,
						(byte) 0, TaskMonitor.DUMMY, false);

			AllCopiers.REFERENCES.copy(view, tb.range(0x55550000, 0x5555ffff), program, paddr,
				TaskMonitor.DUMMY);
		}

		List<Reference> references = new ArrayList<>();
		program.getReferenceManager().getReferenceIterator(paddr).forEachRemaining(references::add);

		assertEquals(1, references.size());
		Reference ref;

		ref = references.get(0);
		assertEquals(tb.addr(stSpace, 0x55550123), ref.getFromAddress());
		assertEquals(tb.addr(stSpace, 0x55550321), ref.getToAddress());
		assertEquals(RefType.COMPUTED_CALL, ref.getReferenceType());
		assertEquals(SourceType.USER_DEFINED, ref.getSource());
		assertEquals(-1, ref.getOperandIndex());
	}

	@Test
	public void testComments() throws Exception {
		createTrace();
		createProgram(getSLEIGH_X86_64_LANGUAGE());
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		assertTrue(AllCopiers.COMMENTS.isAvailable(view, program));

		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.createRegion(".text", 0, tb.range(0x55550000, 0x5555ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);

			Listing listing = view.getListing();
			listing.setComment(tb.addr(0x55550123), CodeUnit.EOL_COMMENT, "Test EOL Comment");
			listing.setComment(tb.addr(0x55550321), CodeUnit.PLATE_COMMENT, "Test Plate Comment");
		}

		Address paddr = tb.addr(stSpace, 0x55550000);
		try (Transaction tx = program.openTransaction("Init")) {
			program.getMemory()
					.createInitializedBlock(".text", paddr, 0x10000,
						(byte) 0, TaskMonitor.DUMMY, false);

			AllCopiers.COMMENTS.copy(view, tb.range(0x55550000, 0x5555ffff), program, paddr,
				TaskMonitor.DUMMY);
		}

		Set<Address> addresses = new HashSet<>();
		Listing listing = program.getListing();
		listing.getCommentAddressIterator(program.getMemory(), true)
				.forEachRemaining(addresses::add);

		assertEquals(Set.of(tb.addr(stSpace, 0x55550123), tb.addr(stSpace, 0x55550321)), addresses);
		assertEquals("Test EOL Comment",
			listing.getComment(CodeUnit.EOL_COMMENT, tb.addr(stSpace, 0x55550123)));
		assertEquals("Test Plate Comment",
			listing.getComment(CodeUnit.PLATE_COMMENT, tb.addr(stSpace, 0x55550321)));
	}
}
