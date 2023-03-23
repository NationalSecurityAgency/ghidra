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
package ghidra.app.plugin.core.debug.stack;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.Predicate;

import org.junit.Test;

import db.Transaction;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.Unique;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.*;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.disassemble.TraceDisassembleCommand;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.stack.vars.*;
import ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueRow.*;
import ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.stack.StackUnwindWarning.*;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.disassembler.DisassemblerPlugin;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.app.services.DebuggerEmulationService.EmulationResult;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.lifecycle.Unfinished;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue;
import ghidra.pcode.exec.DebuggerPcodeUtils.WatchValuePcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.Scheduler;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

public class StackUnwinderTest extends AbstractGhidraHeadedDebuggerGUITest {

	public static final AssemblySelector NO_16BIT_CALLS = new AssemblySelector() {
		@Override
		public AssemblyResolvedPatterns select(AssemblyResolutionResults rr,
				AssemblyPatternBlock ctx) throws AssemblySemanticException {
			for (AssemblyResolvedPatterns res : filterCompatibleAndSort(rr, ctx)) {
				byte[] ins = res.getInstruction().getVals();
				// HACK to avoid 16-bit CALL.... TODO: Why does this happen?
				if (ins.length >= 2 && ins[0] == (byte) 0x66 && ins[1] == (byte) 0xe8) {
					System.err.println(
						"Filtered 16-bit call " + NumericUtilities.convertBytesToString(ins));
					continue;
				}
				return AssemblyResolution.resolved(res.getInstruction().fillMask(),
					res.getContext(), "Selected", null, null, null);
			}
			throw new AssemblySemanticException(semanticErrors);
		}
	};

	protected void createProgram(String languageID, String cSpecID) throws IOException {
		Language language = getLanguageService().getLanguage(new LanguageID(languageID));
		CompilerSpec cSpec = cSpecID == null ? language.getDefaultCompilerSpec()
				: language.getCompilerSpecByID(new CompilerSpecID(cSpecID));
		createProgram(language, cSpec);
	}

	Address bodyInstr;
	Address retInstr;
	Address globalRefInstr;
	Address stackRefInstr;
	Address registerRefInstr;
	Address funcInstr;

	CodeBrowserPlugin codeBrowserPlugin;
	ListingPanel staticListing;
	DebuggerListingPlugin listingPlugin;
	ListingPanel dynamicListing;
	DebuggerControlService editingService;
	DebuggerEmulationService emuService;
	DecompilerProvider decompilerProvider;
	DecompilerPanel decompilerPanel;

	protected Address stack(long offset) {
		return program.getCompilerSpec().getStackSpace().getAddress(offset);
	}

	protected Register register(String name) {
		return program.getLanguage().getRegister(name);
	}

	protected Function createSumSquaresProgramX86_32() throws Throwable {
		createProgram("x86:LE:32:default", "gcc");
		intoProject(program);
		try (Transaction tx = program.openTransaction("Assemble")) {
			Address entry = addr(program, 0x00400000);
			program.getMemory()
					.createInitializedBlock(".text", entry, 0x1000, (byte) 0, monitor, false);
			Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
			AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

			buf.assemble("PUSH EBP");
			buf.assemble("MOV EBP, ESP");
			buf.assemble("SUB ESP, 0x10");

			buf.assemble("XOR ECX,ECX");
			buf.assemble("MOV dword ptr [EBP+-4], ECX");
			buf.assemble("MOV dword ptr [EBP+-8], ECX");
			Address jumpCheck = buf.getNext();
			buf.assemble("JMP 0x" + buf.getNext());
			Address labelLoop = buf.getNext();
			buf.assemble("MOV EAX, dword ptr [EBP+-4]");
			bodyInstr = buf.getNext();
			buf.assemble("IMUL EAX, dword ptr [EBP+-4]");
			buf.assemble("ADD dword ptr [EBP+-8], EAX");

			buf.assemble("INC dword ptr [EBP+-4]");
			Address labelCheck = buf.getNext();
			buf.assemble(jumpCheck, "JMP 0x" + labelCheck);
			buf.assemble("MOV EAX, dword ptr [EBP+-4]");
			buf.assemble("CMP EAX, dword ptr [EBP+8]");
			buf.assemble("JLE 0x" + labelLoop);

			buf.assemble("MOV EAX, dword ptr [EBP+-8]");

			buf.assemble("LEAVE");
			retInstr = buf.getNext();
			buf.assemble("RET");

			byte[] bytes = buf.getBytes();
			program.getMemory().setBytes(entry, bytes);

			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			dis.disassemble(entry, null);

			Function function = program.getFunctionManager()
					.createFunction("sumSquares", entry,
						new AddressSet(entry, entry.add(bytes.length - 1)),
						SourceType.USER_DEFINED);

			function.updateFunction("__cdecl",
				new ReturnParameterImpl(IntegerDataType.dataType, program),
				List.of(
					new ParameterImpl("n", IntegerDataType.dataType, program)),
				FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.ANALYSIS);
			function.addLocalVariable(
				new LocalVariableImpl("i", IntegerDataType.dataType, -8, program),
				SourceType.USER_DEFINED);
			function.addLocalVariable(
				new LocalVariableImpl("sum", IntegerDataType.dataType, -12, program),
				SourceType.USER_DEFINED);
			return function;
		}
	}

	protected Function createFibonacciProgramX86_32() throws Throwable {
		createProgram("x86:LE:32:default", "gcc");
		intoProject(program);
		try (Transaction tx = program.openTransaction("Assemble")) {
			Address entry = addr(program, 0x00400000);
			program.getMemory()
					.createInitializedBlock(".text", entry, 0x1000, (byte) 0, monitor, false);
			Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
			AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

			buf.assemble("PUSH EBP");
			buf.assemble("MOV EBP, ESP");

			buf.assemble("CMP dword ptr [EBP+8], 1");
			Address jumpBase = buf.getNext();
			buf.assemble("JBE 0x" + buf.getNext());

			// Recursive case. Let EDX be sum
			// sum = fib(n - 1)
			buf.assemble("MOV ECX, dword ptr [EBP+8]");
			buf.assemble("DEC ECX");
			buf.assemble("PUSH ECX"); // pass n - 1
			buf.assemble("CALL 0x" + entry);
			buf.assemble("ADD ESP, 4"); // Clear parameters
			registerRefInstr = buf.getNext();
			buf.assemble("MOV EDX, EAX");
			// sum += fib(n - 2)
			buf.assemble("MOV ECX, dword ptr [EBP+8]");
			buf.assemble("SUB ECX, 2");
			buf.assemble("PUSH EDX"); // Caller Save EDX
			buf.assemble("PUSH ECX"); // pass n - 2
			buf.assemble("CALL 0x" + entry);
			buf.assemble("ADD ESP, 4"); // Clear parameters
			buf.assemble("POP EDX"); // Restore EDX
			buf.assemble("ADD EAX, EDX");

			Address labelRet = buf.getNext();
			buf.assemble("LEAVE");
			retInstr = buf.getNext();
			buf.assemble("RET");

			Address labelBase = buf.getNext();
			buf.assemble(jumpBase, "JBE 0x" + labelBase);
			stackRefInstr = buf.getNext();
			buf.assemble("MOV EAX, dword ptr [EBP+8]");
			buf.assemble("JMP 0x" + labelRet);

			byte[] bytes = buf.getBytes();
			program.getMemory().setBytes(entry, bytes);

			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			dis.disassemble(entry, null);

			Function function = program.getFunctionManager()
					.createFunction("fib", entry,
						new AddressSet(entry, entry.add(bytes.length - 1)),
						SourceType.USER_DEFINED);

			function.updateFunction("__cdecl",
				new ReturnParameterImpl(UnsignedIntegerDataType.dataType, program),
				List.of(
					new ParameterImpl("n", UnsignedIntegerDataType.dataType, program)),
				FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.ANALYSIS);
			// NOTE: The decompiler doesn't actually use sum.... For some reason, it re-uses n
			// Still, in the tests, I can use uVar1 (EAX) as a register variable
			function.addLocalVariable(
				new LocalVariableImpl("sum", 0, UnsignedIntegerDataType.dataType, register("EDX"),
					program),
				SourceType.USER_DEFINED);

			Instruction ins = program.getListing().getInstructionAt(stackRefInstr);
			ins.addOperandReference(1, stack(4), RefType.READ, SourceType.ANALYSIS);
			return function;
		}
	}

	protected Function createCallExternProgramX86_32() throws Throwable {
		createProgram("x86:LE:32:default", "gcc");
		intoProject(program);
		Address entry;
		try (Transaction tx = program.openTransaction("Assemble")) {
			entry = addr(program, 0x00400000);
			Address externs = addr(program, 0x00700000);
			program.getMemory()
					.createInitializedBlock(".text", entry, 0x1000, (byte) 0, monitor, false);
			program.getMemory()
					.createUninitializedBlock(MemoryBlock.EXTERNAL_BLOCK_NAME, externs, 0x10,
						false);

			program.getFunctionManager()
					.createFunction("myExtern", externs, new AddressSet(externs),
						SourceType.USER_DEFINED);

			Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
			AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

			buf.assemble("PUSH EBP");
			buf.assemble("MOV EBP, ESP");
			buf.assemble("SUB ESP, 0x10");

			buf.assemble("XOR ECX,ECX");
			buf.assemble("MOV dword ptr [EBP+-4], ECX");
			buf.assemble("MOV dword ptr [EBP+-8], ECX");
			Address jumpCheck = buf.getNext();
			buf.assemble("JMP 0x" + buf.getNext());
			Address labelLoop = buf.getNext();
			buf.assemble("MOV EAX, dword ptr [EBP+-4]");
			bodyInstr = buf.getNext();
			buf.assemble("PUSH EAX");
			buf.assemble("CALL 0x" + externs);
			buf.assemble("ADD ESP, 0x4");
			buf.assemble("ADD dword ptr [EBP+-8], EAX");

			buf.assemble("INC dword ptr [EBP+-4]");
			Address labelCheck = buf.getNext();
			buf.assemble(jumpCheck, "JMP 0x" + labelCheck);
			buf.assemble("MOV EAX, dword ptr [EBP+-4]");
			buf.assemble("CMP EAX, dword ptr [EBP+8]");
			buf.assemble("JL 0x" + labelLoop);

			buf.assemble("MOV EAX, dword ptr [EBP+-8]");

			buf.assemble("LEAVE");
			buf.assemble("RET");

			byte[] bytes = buf.getBytes();
			program.getMemory().setBytes(entry, bytes);

			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			dis.disassemble(entry, null);

			return program.getFunctionManager()
					.createFunction("sumReturns", entry,
						new AddressSet(entry, entry.add(bytes.length - 1)),
						SourceType.USER_DEFINED);
		}
	}

	protected Function createCallPointerProgramX86_32() throws Throwable {
		createProgram("x86:LE:32:default", "gcc");
		intoProject(program);
		Address entry;
		try (Transaction tx = program.openTransaction("Assemble")) {
			entry = addr(program, 0x00400000);
			program.getMemory()
					.createInitializedBlock(".text", entry, 0x1000, (byte) 0, monitor, false);

			Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
			AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

			buf.assemble("PUSH EBP");
			buf.assemble("MOV EBP, ESP");
			buf.assemble("SUB ESP, 0x10");

			buf.assemble("XOR ECX,ECX");
			buf.assemble("MOV dword ptr [EBP+-4], ECX");
			buf.assemble("MOV dword ptr [EBP+-8], ECX");
			Address jumpCheck = buf.getNext();
			buf.assemble("JMP 0x" + buf.getNext());
			Address labelLoop = buf.getNext();
			buf.assemble("MOV EDX, dword ptr [EBP+-4]");
			buf.assemble("MOV EAX, dword ptr [EBP+12]");
			bodyInstr = buf.getNext();
			buf.assemble("PUSH EDX");
			buf.assemble("CALL EAX");
			buf.assemble("ADD ESP, 0x4");
			buf.assemble("ADD dword ptr [EBP+-8], EAX");

			buf.assemble("INC dword ptr [EBP+-4]");
			Address labelCheck = buf.getNext();
			buf.assemble(jumpCheck, "JMP 0x" + labelCheck);
			buf.assemble("MOV EAX, dword ptr [EBP+-4]");
			buf.assemble("CMP EAX, dword ptr [EBP+8]");
			buf.assemble("JL 0x" + labelLoop);

			buf.assemble("MOV EAX, dword ptr [EBP+-8]");

			buf.assemble("LEAVE");
			buf.assemble("RET");

			byte[] bytes = buf.getBytes();
			program.getMemory().setBytes(entry, bytes);

			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			dis.disassemble(entry, null);

			return program.getFunctionManager()
					.createFunction("sumReturns", entry,
						new AddressSet(entry, entry.add(bytes.length - 1)),
						SourceType.USER_DEFINED);
		}
	}

	protected Function createSetGlobalProgramX86_32() throws Throwable {
		createProgram("x86:LE:32:default", "gcc");
		intoProject(program);

		try (Transaction tx = program.openTransaction("Assemble")) {
			Address entry = addr(program, 0x00400000);
			program.getMemory()
					.createInitializedBlock(".text", entry, 0x1000, (byte) 0, monitor, false);
			Address global = addr(program, 0x00600000);
			program.getMemory()
					.createInitializedBlock(".data", global, 0x1000, (byte) 0, monitor, false);

			Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
			AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

			buf.assemble("MOV EAX, 0xdeadbeef");
			globalRefInstr = buf.getNext();
			buf.assemble("MOV dword ptr [0x00600000], EAX");
			retInstr = buf.getNext();
			buf.assemble("RET");

			byte[] bytes = buf.getBytes();
			program.getMemory().setBytes(entry, bytes);

			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			dis.disassemble(entry, null);

			program.getListing().createData(global, IntegerDataType.dataType, 4);
			program.getSymbolTable().createLabel(global, "myGlobal", SourceType.USER_DEFINED);

			return program.getFunctionManager()
					.createFunction("setGlobal", entry,
						new AddressSet(entry, entry.add(bytes.length - 1)),
						SourceType.USER_DEFINED);
		}
	}

	protected Function createFillStructProgramX86_32() throws Throwable {
		createProgram("x86:LE:32:default", "gcc");
		intoProject(program);

		try (Transaction tx = program.openTransaction("Assemble")) {
			ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
			Structure structure = new StructureDataType("MyStruct", 0, dtm);
			structure.add(WordDataType.dataType, "y", "");
			structure.add(ByteDataType.dataType, "m", "");
			structure.add(ByteDataType.dataType, "d", "");
			structure =
				(Structure) dtm.addDataType(structure, DataTypeConflictHandler.DEFAULT_HANDLER);

			Address entry = addr(program, 0x00400000);
			program.getMemory()
					.createInitializedBlock(".text", entry, 0x1000, (byte) 0, monitor, false);
			Address global = addr(program, 0x00600000);
			MemoryBlock dataBlock = program.getMemory()
					.createInitializedBlock(".data", global, 0x1000, (byte) 0, monitor, false);
			dataBlock.setWrite(true);

			Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
			AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

			buf.assemble("PUSH EBP");
			buf.assemble("MOV EBP, ESP");
			buf.assemble("SUB ESP, 4");
			buf.assemble("LEA EAX, [0x00600000]");
			buf.assemble("PUSH EAX");
			Address call1 = buf.getNext();
			buf.assemble("CALL 0x" + buf.getNext());
			buf.assemble("ADD ESP, 4");
			buf.assemble("LEA EAX, [ESP]");
			buf.assemble("PUSH EAX");
			Address call2 = buf.getNext();
			buf.assemble("CALL 0x" + buf.getNext());
			buf.assemble("ADD ESP, 4");
			buf.assemble("MOVZX EAX, word ptr [ESP]");
			buf.assemble("MOVZX EDX, byte ptr [0x00600002]");
			buf.assemble("ADD EAX, EDX");
			buf.assemble("LEAVE");
			buf.assemble("RET");

			funcInstr = buf.getNext();
			buf.assemble(call1, "CALL 0x" + funcInstr);
			buf.assemble(call2, "CALL 0x" + funcInstr);

			buf.assemble("MOV EAX, dword ptr [ESP+4]");
			buf.assemble("MOV word ptr [EAX], 2022");
			buf.assemble("MOV byte ptr [EAX+2], 12");
			buf.assemble("MOV byte ptr [EAX+3], 9");
			retInstr = buf.getNext();
			buf.assemble("RET");
			Address end = buf.getNext();

			byte[] bytes = buf.getBytes();
			program.getMemory().setBytes(entry, bytes);

			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			dis.disassemble(entry, null);

			program.getListing().createData(global, structure, 4);
			program.getSymbolTable().createLabel(global, "myGlobal", SourceType.USER_DEFINED);

			Function funFillStruct = program.getFunctionManager()
					.createFunction("fillStruct", funcInstr,
						new AddressSet(funcInstr, end.previous()), SourceType.USER_DEFINED);
			funFillStruct.updateFunction("__cdecl", null,
				List.of(
					new ParameterImpl("s", new PointerDataType(structure), program)),
				FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.ANALYSIS);

			Function main = program.getFunctionManager()
					.createFunction("main", entry, new AddressSet(entry, funcInstr.previous()),
						SourceType.USER_DEFINED);
			main.updateFunction("__cdecl",
				new ReturnParameterImpl(DWordDataType.dataType, program),
				FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.ANALYSIS);
			main.addLocalVariable(
				new LocalVariableImpl("myStack", structure, -8, program),
				SourceType.ANALYSIS);
			return main;
		}
	}

	protected Function createFillStructArrayProgramX86_32() throws Throwable {
		createProgram("x86:LE:32:default", "gcc");
		intoProject(program);

		try (Transaction tx = program.openTransaction("Assemble")) {
			ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
			Structure structure = new StructureDataType("MyStruct", 0, dtm);
			structure.add(WordDataType.dataType, "y", "");
			structure.add(ByteDataType.dataType, "m", "");
			structure.add(ByteDataType.dataType, "d", "");
			structure =
				(Structure) dtm.addDataType(structure, DataTypeConflictHandler.DEFAULT_HANDLER);

			Address entry = addr(program, 0x00400000);
			program.getMemory()
					.createInitializedBlock(".text", entry, 0x1000, (byte) 0, monitor, false);
			Address global = addr(program, 0x00600000);
			MemoryBlock dataBlock = program.getMemory()
					.createInitializedBlock(".data", global, 0x1000, (byte) 0, monitor, false);
			dataBlock.setWrite(true);

			Assembler asm = Assemblers.getAssembler(program.getLanguage(), NO_16BIT_CALLS);
			AssemblyBuffer buf = new AssemblyBuffer(asm, entry);

			buf.assemble("PUSH EBP");
			buf.assemble("MOV EBP, ESP");
			buf.assemble("PUSH 2");
			buf.assemble("LEA EAX, [0x00600000]");
			buf.assemble("PUSH EAX");
			Address call = buf.getNext();
			buf.assemble("CALL 0x" + buf.getNext());
			buf.assemble("ADD ESP, 8");
			buf.assemble("LEAVE");
			buf.assemble("RET");

			funcInstr = buf.getNext();
			buf.assemble(call, "CALL 0x" + funcInstr);

			buf.assemble("MOV EAX, dword ptr [ESP+4]");
			buf.assemble("MOV ECX, dword ptr [ESP+8]");
			//buf.assemble("LEA EAX, [EAX+ECX*4]");
			buf.assemble("MOV word ptr [EAX+ECX*4], 2022");
			buf.assemble("MOV byte ptr [EAX+ECX*4+2], 12");
			buf.assemble("MOV byte ptr [EAX+ECX*4+3], 9");
			retInstr = buf.getNext();
			buf.assemble("RET");
			Address end = buf.getNext();

			byte[] bytes = buf.getBytes();
			program.getMemory().setBytes(entry, bytes);

			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			dis.disassemble(entry, null);

			program.getListing()
					.createData(global,
						new ArrayDataType(structure, 10, 4, program.getDataTypeManager()));
			program.getSymbolTable().createLabel(global, "myGlobal", SourceType.USER_DEFINED);

			Function funFillStruct = program.getFunctionManager()
					.createFunction("fillStruct", funcInstr,
						new AddressSet(funcInstr, end.previous()), SourceType.USER_DEFINED);
			funFillStruct.updateFunction("__cdecl", null,
				List.of(
					new ParameterImpl("s", new PointerDataType(structure), program),
					new ParameterImpl("i", IntegerDataType.dataType, program)),
				FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.ANALYSIS);

			Function main = program.getFunctionManager()
					.createFunction("main", entry, new AddressSet(entry, funcInstr.previous()),
						SourceType.USER_DEFINED);
			main.updateFunction("__cdecl",
				new ReturnParameterImpl(DWordDataType.dataType, program),
				FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.ANALYSIS);
			return main;
		}
	}

	@Test
	public void testComputeUnwindInfoX86_32() throws Throwable {
		addPlugin(tool, CodeBrowserPlugin.class);

		Function function = createSumSquaresProgramX86_32();
		Address entry = function.getEntryPoint();

		programManager.openProgram(program);

		UnwindAnalysis ua = new UnwindAnalysis(program);

		UnwindInfo infoAtEntry = ua.computeUnwindInfo(entry, monitor);
		assertEquals(
			new UnwindInfo(function, 0, 4, stack(0), Map.of(), new StackUnwindWarningSet()),
			infoAtEntry);

		UnwindInfo infoAtBody = ua.computeUnwindInfo(bodyInstr, monitor);
		assertEquals(new UnwindInfo(function, -20, 4, stack(0),
			Map.of(
				register("EBP"), stack(-4)),
			new StackUnwindWarningSet()),
			infoAtBody);
	}

	@Test
	public void testComputeUnwindInfoWithExternCallsX86_32() throws Throwable {
		addPlugin(tool, CodeBrowserPlugin.class);

		Function function = createCallExternProgramX86_32();
		Address entry = function.getEntryPoint();
		Function myExtern =
			(Function) Unique.assertOne(program.getSymbolTable().getSymbols("myExtern"))
					.getObject();

		programManager.openProgram(program);

		UnwindAnalysis ua = new UnwindAnalysis(program);

		UnwindInfo infoAtEntry = ua.computeUnwindInfo(entry, monitor);
		assertEquals(
			new UnwindInfo(function, 0, 4, stack(0), Map.of(), new StackUnwindWarningSet()),
			infoAtEntry);

		UnwindInfo infoAtBody = ua.computeUnwindInfo(bodyInstr, monitor);
		assertEquals(new UnwindInfo(function, -20, 4, stack(0),
			Map.of(
				register("EBP"), stack(-4)),
			new StackUnwindWarningSet(
				new UnspecifiedConventionStackUnwindWarning(myExtern),
				new UnknownPurgeStackUnwindWarning(myExtern))),
			infoAtBody);
	}

	@Test
	public void testComputeUnwindInfoWithIndirectCallsX86_32() throws Throwable {
		addPlugin(tool, CodeBrowserPlugin.class);
		addPlugin(tool, DecompilePlugin.class);

		Function function = createCallPointerProgramX86_32();
		Address entry = function.getEntryPoint();

		programManager.openProgram(program);

		UnwindAnalysis ua = new UnwindAnalysis(program);

		UnwindInfo infoAtEntry = ua.computeUnwindInfo(entry, monitor);
		assertEquals(
			new UnwindInfo(function, 0, 4, stack(0), Map.of(), new StackUnwindWarningSet()),
			infoAtEntry);

		UnwindInfo infoAtBody = ua.computeUnwindInfo(bodyInstr, monitor);
		DataType ptr2Undef = new PointerDataType(DataType.DEFAULT, program.getDataTypeManager());
		assertEquals(new UnwindInfo(function, -20, 4, stack(0),
			Map.of(
				register("EBP"), stack(-4)),
			new StackUnwindWarningSet(
				new UnexpectedTargetTypeStackUnwindWarning(ptr2Undef))),
			infoAtBody);
	}

	@Test
	public void testUnwindTopFrameX86_32() throws Throwable {
		addPlugin(tool, CodeBrowserPlugin.class);
		addPlugin(tool, DebuggerListingPlugin.class);
		addPlugin(tool, DisassemblerPlugin.class);
		addPlugin(tool, DecompilePlugin.class);
		DebuggerControlService editingService =
			addPlugin(tool, DebuggerControlServicePlugin.class);
		DebuggerEmulationService emuService = addPlugin(tool, DebuggerEmulationServicePlugin.class);

		Function function = createSumSquaresProgramX86_32();
		Address entry = function.getEntryPoint();

		programManager.openProgram(program);

		useTrace(ProgramEmulationUtils.launchEmulationTrace(program, entry, this));
		tb.trace.release(this);
		TraceThread thread = Unique.assertOne(tb.trace.getThreadManager().getAllThreads());
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
		StateEditor editor = editingService.createStateEditor(tb.trace);

		DebuggerCoordinates atSetup = traceManager.getCurrent();
		StackUnwinder unwinder = new StackUnwinder(tool, atSetup.getPlatform());
		AnalysisUnwoundFrame<WatchValue> frameAtSetup = unwinder.start(atSetup, monitor);

		Parameter param1 = function.getParameter(0);
		waitOn(frameAtSetup.setValue(editor, param1, BigInteger.valueOf(4)));
		waitForTasks();

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[0]", Lifespan.nowOn(0), retInstr, Set.of(),
						Set.of(TraceBreakpointKind.SW_EXECUTE), true, "capture return value");
		}

		EmulationResult result = emuService.run(atSetup.getPlatform(), atSetup.getTime(), monitor,
			Scheduler.oneThread(thread));
		Msg.debug(this, "Broke after " + result.schedule());

		traceManager.activateTime(result.schedule());
		waitForTasks();
		DebuggerCoordinates after = traceManager.getCurrent();
		AnalysisUnwoundFrame<WatchValue> frameAfter = unwinder.start(after, monitor);

		WatchValuePcodeArithmetic wa =
			WatchValuePcodeArithmetic.forLanguage(after.getPlatform().getLanguage());
		for (Variable variable : function.getVariables(null)) {
			BigInteger value = wa.toBigInteger(frameAfter.getValue(variable), Purpose.INSPECT);
			Msg.debug(this, variable + " = " + value);
		}
		Variable retVar = function.getReturn();
		BigInteger retVal = wa.toBigInteger(frameAfter.getValue(retVar), Purpose.INSPECT);
		Msg.debug(this, "Return " + retVal);
		assertEquals(BigInteger.valueOf(30), retVal);
	}

	@Test
	public void testUnwindRecursiveX86_32() throws Throwable {
		addPlugin(tool, CodeBrowserPlugin.class);
		addPlugin(tool, DebuggerListingPlugin.class);
		addPlugin(tool, DisassemblerPlugin.class);
		addPlugin(tool, DecompilePlugin.class);
		DebuggerControlService editingService =
			addPlugin(tool, DebuggerControlServicePlugin.class);
		DebuggerEmulationService emuService = addPlugin(tool, DebuggerEmulationServicePlugin.class);

		Function function = createFibonacciProgramX86_32();
		Address entry = function.getEntryPoint();

		programManager.openProgram(program);

		useTrace(ProgramEmulationUtils.launchEmulationTrace(program, entry, this));
		tb.trace.release(this);
		TraceThread thread = Unique.assertOne(tb.trace.getThreadManager().getAllThreads());
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
		StateEditor editor = editingService.createStateEditor(tb.trace);

		DebuggerCoordinates atSetup = traceManager.getCurrent();
		StackUnwinder unwinder = new StackUnwinder(tool, atSetup.getPlatform());
		AnalysisUnwoundFrame<WatchValue> frameAtSetup = unwinder.start(atSetup, monitor);

		Parameter param1 = function.getParameter(0);
		waitOn(frameAtSetup.setValue(editor, param1, BigInteger.valueOf(9)));
		waitOn(frameAtSetup.setReturnAddress(editor, tb.addr(0xdeadbeef)));
		waitForTasks();

		TraceBreakpoint bptUnwind;
		try (Transaction tx = tb.startTransaction()) {
			bptUnwind = tb.trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[0]", Lifespan.nowOn(0), retInstr,
						Set.of(),
						Set.of(TraceBreakpointKind.SW_EXECUTE), true, "unwind stack");
			tb.trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[1]", Lifespan.nowOn(0), tb.addr(0xdeadbeef),
						Set.of(),
						Set.of(TraceBreakpointKind.SW_EXECUTE), true, "capture return value");
		}

		EmulationResult result = emuService.run(atSetup.getPlatform(), atSetup.getTime(), monitor,
			Scheduler.oneThread(thread));
		Msg.debug(this, "Broke after " + result.schedule());

		traceManager.activateTime(result.schedule());
		waitForTasks();
		DebuggerCoordinates tallest = traceManager.getCurrent();
		AnalysisUnwoundFrame<WatchValue> frameTallest = unwinder.start(tallest, monitor);
		while (true) {
			Msg.debug(this, "Frame " + frameTallest.getLevel());
			for (Variable variable : function.getVariables(null)) {
				try {
					WatchValue value = frameTallest.getValue(variable);
					Msg.debug(this, "  " + variable + " = " + value);
				}
				catch (UnwindException e) {
					Msg.debug(this, "  Cannot get " + variable + ": " + e);
				}
			}
			try {
				frameTallest = frameTallest.unwindNext(monitor);
			}
			catch (NoSuchElementException e) {
				break;
			}
		}

		try (Transaction tx = tb.startTransaction()) {
			bptUnwind.delete();
		}

		result = emuService.run(tallest.getPlatform(), tallest.getTime(), monitor,
			Scheduler.oneThread(thread));

		// Step back, so PC is in the function
		traceManager.activateTime(result.schedule().steppedBackward(tb.trace, 1));
		waitForTasks();
		DebuggerCoordinates after = traceManager.getCurrent();
		AnalysisUnwoundFrame<WatchValue> frameAfter = unwinder.start(after, monitor);

		for (Variable variable : function.getVariables(null)) {
			WatchValue value = frameAfter.getValue(variable);
			Msg.debug(this, variable + " = " + value);
		}
		Variable retVar = function.getReturn();
		WatchValue retVal = frameAfter.getValue(retVar);
		Msg.debug(this, "Return " + retVal);
		assertEquals(BigInteger.valueOf(34), retVal.toBigInteger(false));
	}

	@Test
	public void testCreateFramesAtEntryX86_32() throws Throwable {
		addPlugin(tool, CodeBrowserPlugin.class);
		addPlugin(tool, DebuggerListingPlugin.class);
		addPlugin(tool, DisassemblerPlugin.class);
		addPlugin(tool, DecompilePlugin.class);

		Function function = createFibonacciProgramX86_32();
		Address entry = function.getEntryPoint();

		programManager.openProgram(program);

		useTrace(ProgramEmulationUtils.launchEmulationTrace(program, entry, this));
		tb.trace.release(this);
		TraceThread thread = Unique.assertOne(tb.trace.getThreadManager().getAllThreads());
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		DebuggerCoordinates atSetup = traceManager.getCurrent();
		try (Transaction tx = tb.startTransaction()) {
			new UnwindStackCommand(tool, atSetup).applyTo(tb.trace, monitor);
		}
		waitForDomainObject(tb.trace);

		ListingUnwoundFrame frame = VariableValueUtils.locateFrame(tool, atSetup, function);
		TraceData data = frame.getData();
		assertEquals(8, data.getLength());
		assertEquals(2, data.getNumComponents());
		assertEquals("return_address", data.getComponent(0).getFieldName());
		assertEquals("param_n", data.getComponent(1).getFieldName());

		assertNull(VariableValueUtils.locateFrame(tool, atSetup.frame(1), function));
	}

	protected static void assertField(Data data, String name, Object value) {
		assertEquals(name, data.getFieldName());
		assertEquals(value, data.getValue());
	}

	protected void addPlugins() throws Throwable {
		codeBrowserPlugin = addPlugin(tool, CodeBrowserPlugin.class);
		staticListing = codeBrowserPlugin.getProvider().getListingPanel();
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		dynamicListing = listingPlugin.getProvider().getListingPanel();
		addPlugin(tool, DisassemblerPlugin.class);
		addPlugin(tool, DecompilePlugin.class);
		editingService = addPlugin(tool, DebuggerControlServicePlugin.class);
		emuService = addPlugin(tool, DebuggerEmulationServicePlugin.class);

		decompilerProvider = waitForComponentProvider(DecompilerProvider.class);
		decompilerPanel = decompilerProvider.getDecompilerPanel();
	}

	protected Function runToTallestRecursionAndCreateFrames(int n) throws Throwable {
		addPlugins();

		Function function = createFibonacciProgramX86_32();
		Address entry = function.getEntryPoint();

		programManager.openProgram(program);

		useTrace(ProgramEmulationUtils.launchEmulationTrace(program, entry, this));
		tb.trace.release(this);
		TraceThread thread = Unique.assertOne(tb.trace.getThreadManager().getAllThreads());
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
		StateEditor editor = editingService.createStateEditor(tb.trace);

		DebuggerCoordinates atSetup = traceManager.getCurrent();
		StackUnwinder unwinder = new StackUnwinder(tool, atSetup.getPlatform());
		AnalysisUnwoundFrame<WatchValue> frameAtSetup = unwinder.start(atSetup, monitor);

		Parameter paramN = function.getParameter(0);
		assertEquals("n", paramN.getName()); // Sanity
		waitOn(frameAtSetup.setValue(editor, paramN, BigInteger.valueOf(n)));
		waitOn(frameAtSetup.setReturnAddress(editor, tb.addr(0xdeadbeef)));
		waitForTasks();

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[0]", Lifespan.nowOn(0), retInstr,
						Set.of(),
						Set.of(TraceBreakpointKind.SW_EXECUTE), true, "unwind stack");
		}

		EmulationResult result = emuService.run(atSetup.getPlatform(), atSetup.getTime(), monitor,
			Scheduler.oneThread(thread));
		Msg.debug(this, "Broke after " + result.schedule());

		traceManager.activateTime(result.schedule());
		waitForTasks();
		DebuggerCoordinates tallest = traceManager.getCurrent();
		try (Transaction tx = tb.startTransaction()) {
			new UnwindStackCommand(tool, tallest).applyTo(tb.trace, monitor);
		}
		waitForDomainObject(tb.trace);

		return function;
	}

	protected Function runToRetSetGlobalAndCreateFrames() throws Throwable {
		addPlugins();

		Function function = createSetGlobalProgramX86_32();
		Address entry = function.getEntryPoint();

		programManager.openProgram(program);

		useTrace(ProgramEmulationUtils.launchEmulationTrace(program, entry, this));
		tb.trace.release(this);
		TraceThread thread = Unique.assertOne(tb.trace.getThreadManager().getAllThreads());
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
		StateEditor editor = editingService.createStateEditor(tb.trace);
		// Move stack where it shows in UI. Not required, but nice for debugging.
		Register sp = program.getCompilerSpec().getStackPointer();
		waitOn(editor.setRegister(new RegisterValue(sp, BigInteger.valueOf(0x4ff0))));

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[0]", Lifespan.nowOn(0), retInstr,
						Set.of(),
						Set.of(TraceBreakpointKind.SW_EXECUTE), true, "unwind stack");
		}

		DebuggerCoordinates atSetup = traceManager.getCurrent();
		EmulationResult result = emuService.run(atSetup.getPlatform(), atSetup.getTime(), monitor,
			Scheduler.oneThread(thread));
		Msg.debug(this, "Broke after " + result.schedule());

		traceManager.activateTime(result.schedule());
		waitForTasks();
		DebuggerCoordinates atRet = traceManager.getCurrent();
		try (Transaction tx = tb.startTransaction()) {
			new UnwindStackCommand(tool, atRet).applyTo(tb.trace, monitor);
		}
		waitForDomainObject(tb.trace);

		return function;
	}

	protected Function runToRetFillStructAndCreateFrames() throws Throwable {
		addPlugins();

		Function function = createFillStructProgramX86_32();
		Address entry = function.getEntryPoint();

		programManager.openProgram(program);

		useTrace(ProgramEmulationUtils.launchEmulationTrace(program, entry, this));
		tb.trace.release(this);
		TraceThread thread = Unique.assertOne(tb.trace.getThreadManager().getAllThreads());
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
		StateEditor editor = editingService.createStateEditor(tb.trace);
		// Move stack where it shows in UI. Not required, but nice for debugging.
		Register sp = program.getCompilerSpec().getStackPointer();
		waitOn(editor.setRegister(new RegisterValue(sp, BigInteger.valueOf(0x4ff0))));

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[0]", Lifespan.nowOn(0), retInstr,
						Set.of(),
						Set.of(TraceBreakpointKind.SW_EXECUTE), true, "unwind stack");
		}

		DebuggerCoordinates atSetup = traceManager.getCurrent();
		EmulationResult result = emuService.run(atSetup.getPlatform(), atSetup.getTime(), monitor,
			Scheduler.oneThread(thread));
		Msg.debug(this, "Broke after " + result.schedule());

		traceManager.activateTime(result.schedule());
		waitForTasks();
		DebuggerCoordinates atRet = traceManager.getCurrent();
		try (Transaction tx = tb.startTransaction()) {
			new UnwindStackCommand(tool, atRet).applyTo(tb.trace, monitor);
		}
		waitForDomainObject(tb.trace);

		return function;
	}

	protected Function runToRetFillStructArrayAndCreateFrames() throws Throwable {
		addPlugins();

		Function function = createFillStructArrayProgramX86_32();
		Address entry = function.getEntryPoint();

		programManager.openProgram(program);

		useTrace(ProgramEmulationUtils.launchEmulationTrace(program, entry, this));
		tb.trace.release(this);
		TraceThread thread = Unique.assertOne(tb.trace.getThreadManager().getAllThreads());
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
		StateEditor editor = editingService.createStateEditor(tb.trace);
		// Move stack where it shows in UI. Not required, but nice for debugging.
		Register sp = program.getCompilerSpec().getStackPointer();
		waitOn(editor.setRegister(new RegisterValue(sp, BigInteger.valueOf(0x4ff0))));

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[0]", Lifespan.nowOn(0), retInstr,
						Set.of(),
						Set.of(TraceBreakpointKind.SW_EXECUTE), true, "unwind stack");
		}

		DebuggerCoordinates atSetup = traceManager.getCurrent();
		EmulationResult result = emuService.run(atSetup.getPlatform(), atSetup.getTime(), monitor,
			Scheduler.oneThread(thread));
		Msg.debug(this, "Broke after " + result.schedule());

		traceManager.activateTime(result.schedule());
		waitForTasks();
		DebuggerCoordinates atRet = traceManager.getCurrent();
		try (Transaction tx = tb.startTransaction()) {
			new UnwindStackCommand(tool, atRet).applyTo(tb.trace, monitor);
		}
		waitForDomainObject(tb.trace);

		return function;
	}

	@Test
	public void testCreateFramesTallestX86_32() throws Throwable {
		Function function = runToTallestRecursionAndCreateFrames(9);
		DebuggerCoordinates tallest = traceManager.getCurrent();

		ListingUnwoundFrame frame;
		TraceData data;

		frame = VariableValueUtils.locateFrame(tool, tallest, function);
		data = frame.getData();
		assertEquals(8, data.getLength());
		assertEquals(2, data.getNumComponents());
		assertEquals(tb.addr(0x40002c), frame.getProgramCounter());
		assertEquals(tb.addr(0x4fa0), frame.getBasePointer());
		// Saved EBP has already been popped by LEAVE
		assertField(data.getComponent(0), "return_address", tb.addr(0x400013));
		assertField(data.getComponent(1), "param_n", new Scalar(32, 1));

		frame = VariableValueUtils.locateFrame(tool, tallest.frame(1), function);
		data = frame.getData();
		assertEquals(12, data.getLength());
		assertEquals(3, data.getNumComponents());
		assertEquals(tb.addr(0x400013), frame.getProgramCounter());
		assertEquals(tb.addr(0x4fac), frame.getBasePointer());
		assertField(data.getComponent(0), "saved_EBP", new Scalar(32, 0x4fb4));
		assertField(data.getComponent(1), "return_address", tb.addr(0x400013));
		assertField(data.getComponent(2), "param_n", new Scalar(32, 2));

		assertNotNull(VariableValueUtils.locateFrame(tool, tallest.frame(8), function));
		assertNull(VariableValueUtils.locateFrame(tool, tallest.frame(9), function));
	}

	public record HoverLocation(ProgramLocation pLoc, FieldLocation fLoc, Field field,
			ClangToken token) {
	}

	public static <T extends ProgramLocation> HoverLocation findLocation(ListingPanel panel,
			Address address, Class<T> locType, Predicate<T> predicate) {
		Layout layout = panel.getLayout(address);
		int numFields = layout.getNumFields();
		for (int i = 0; i < numFields; i++) {
			Field field = layout.getField(i);
			if (!(field instanceof ListingField listingField)) {
				continue;
			}
			FieldFactory factory = listingField.getFieldFactory();
			int numRows = field.getNumRows();
			for (int r = 0; r < numRows; r++) {
				int numCols = field.getNumCols(r);
				for (int c = 0; c < numCols; c++) {
					ProgramLocation loc = factory.getProgramLocation(r, c, listingField);
					if (!locType.isInstance(loc)) {
						continue;
					}
					if (!predicate.test(locType.cast(loc))) {
						continue;
					}
					return new HoverLocation(loc, new FieldLocation(0, i, r, c), field, null);
				}
			}
		}
		return null;
	}

	public static HoverLocation findVariableLocation(ListingPanel panel, Function function,
			String name) {
		return findLocation(panel, function.getEntryPoint(), VariableLocation.class,
			varLoc -> name.equals(varLoc.getVariable().getName()));
	}

	public static HoverLocation findOperandLocation(ListingPanel panel, Instruction ins,
			Object operand) {
		return findLocation(panel, ins.getAddress(), OperandFieldLocation.class, opLoc -> {
			int subIdx = opLoc.getSubOperandIndex();
			if (subIdx == -1) {
				return false;
			}
			return operand.equals(
				ins.getDefaultOperandRepresentationList(opLoc.getOperandIndex()).get(subIdx));
		});
	}

	protected static void assertTable(Map<RowKey, String> texts, VariableValueTable table) {
		ErrorRow error = (ErrorRow) table.get(RowKey.ERROR);
		if (error != null && !texts.containsKey(RowKey.ERROR)) {
			throw new AssertionError("ErrorRow present", error.error());
		}
		for (Map.Entry<RowKey, String> ent : texts.entrySet()) {
			RowKey key = ent.getKey();
			VariableValueRow row = table.get(key);
			assertNotNull("Missing " + key, row);
			if (key != RowKey.WARNINGS) {
				assertEquals(ent.getValue(), row.toSimpleString());
			}
		}
		assertEquals(texts.size(), table.getNumRows());
	}

	protected VariableValueTable getVariableValueTable(VariableValueHoverService valuesService,
			ProgramLocation programLocation, DebuggerCoordinates current,
			FieldLocation fieldLocation, Field field) throws Throwable {
		VariableValueTable table = new VariableValueTable();
		List<String> warnings = new ArrayList<>();
		waitOn(valuesService.fillVariableValueTable(table, programLocation, current,
			fieldLocation, field, warnings));
		table.add(new WarningsRow(warnings));
		return table;
	}

	@Test
	public void testStackVariableHover() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		Function function = runToTallestRecursionAndCreateFrames(2);
		HoverLocation loc = findVariableLocation(staticListing, function, "n");
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: n",
			RowKey.FRAME, "Frame: 0 fib pc=0040002c sp=00004ff4 base=00004ff4",
			RowKey.STORAGE, "Storage: Stack[0x4]:4",
			RowKey.TYPE, "Type: uint",
			RowKey.LOCATION, "Location: 00004ff8:4",
			RowKey.BYTES, "Bytes: (KNOWN) 01 00 00 00",
			RowKey.INTEGER, "Integer: (KNOWN) 1",
			RowKey.VALUE, "Value: (KNOWN) 1h",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testRegisterVariableHover() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		Function function = runToTallestRecursionAndCreateFrames(2);
		HoverLocation loc = findVariableLocation(staticListing, function, "sum");
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: sum",
			RowKey.FRAME, "Frame: 0 fib pc=0040002c sp=00004ff4 base=00004ff4",
			RowKey.STORAGE, "Storage: EDX:4",
			RowKey.TYPE, "Type: uint",
			RowKey.LOCATION, "Location: EDX:4",
			RowKey.INTEGER, "Integer: (UNKNOWN) 0",
			RowKey.VALUE, "Value: (UNKNOWN) 0h",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testReturnParameterHover() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		Function function = runToTallestRecursionAndCreateFrames(2);
		HoverLocation loc = findVariableLocation(staticListing, function, "<RETURN>");
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: <RETURN>",
			RowKey.FRAME, "Frame: 0 fib pc=0040002c sp=00004ff4 base=00004ff4",
			RowKey.STORAGE, "Storage: EAX:4",
			RowKey.TYPE, "Type: uint",
			RowKey.LOCATION, "Location: EAX:4",
			RowKey.INTEGER, "Integer: (KNOWN) 1",
			RowKey.VALUE, "Value: (KNOWN) 1h",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testGlobalOperandHover() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		runToRetSetGlobalAndCreateFrames();
		Instruction ins = program.getListing().getInstructionAt(globalRefInstr);
		HoverLocation loc = findOperandLocation(staticListing, ins, addr(program, 0x00600000));
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: myGlobal",
			RowKey.STORAGE, "Storage: 00600000:4",
			RowKey.TYPE, "Type: int",
			RowKey.LOCATION, "Location: 00600000:4",
			RowKey.BYTES, "Bytes: (KNOWN) ef be ad de",
			RowKey.INTEGER, """
					Integer: (KNOWN) 3735928559, 0xdeadbeef
					-559038737, -0x21524111""",
			RowKey.VALUE, "Value: (KNOWN) DEADBEEFh",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	protected Instruction copyToDynamic(Instruction stIns) throws Throwable {
		DebuggerStaticMappingService mappingService =
			tool.getService(DebuggerStaticMappingService.class);
		DebuggerCoordinates current = traceManager.getCurrent();
		TraceLocation dynLoc = mappingService.getOpenMappedLocation(tb.trace,
			new ProgramLocation(program, stIns.getAddress()), current.getSnap());
		Address dynamicAddress = dynLoc.getAddress();
		try (Transaction tx = tb.startTransaction()) {
			int length = stIns.getLength();
			assertEquals(length, tb.trace.getMemoryManager()
					.putBytes(current.getSnap(), dynamicAddress,
						ByteBuffer.wrap(stIns.getBytes())));
			new TraceDisassembleCommand(current.getPlatform(), dynamicAddress,
				new AddressSet(dynamicAddress, dynamicAddress.add(length - 1)))
						.applyToTyped(current.getView(), monitor);
		}
		waitForDomainObject(tb.trace);
		return Objects.requireNonNull(tb.trace.getCodeManager()
				.instructions()
				.getAt(current.getViewSnap(), dynamicAddress));
	}

	@Test
	public void testGlobalOperandInTraceHover() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		runToRetSetGlobalAndCreateFrames();
		Instruction ins = copyToDynamic(program.getListing().getInstructionAt(globalRefInstr));
		// I guess the listing needs a moment???
		HoverLocation loc =
			waitForValue(() -> findOperandLocation(dynamicListing, ins, addr(program, 0x00600000)));
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: myGlobal",
			RowKey.STORAGE, "Storage: 00600000:4",
			RowKey.TYPE, "Type: int",
			RowKey.LOCATION, "Location: 00600000:4",
			RowKey.BYTES, "Bytes: (KNOWN) ef be ad de",
			RowKey.INTEGER, """
					Integer: (KNOWN) 3735928559, 0xdeadbeef
					-559038737, -0x21524111""",
			RowKey.VALUE, "Value: (KNOWN) DEADBEEFh",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testStackReferenceHover() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		runToTallestRecursionAndCreateFrames(2);
		Instruction ins = program.getListing().getInstructionAt(stackRefInstr);
		HoverLocation loc = findOperandLocation(staticListing, ins, new Scalar(32, 8));
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: n",
			RowKey.FRAME, "Frame: 0 fib pc=0040002c sp=00004ff4 base=00004ff4",
			RowKey.STORAGE, "Storage: Stack[0x4]:4",
			RowKey.TYPE, "Type: uint",
			RowKey.LOCATION, "Location: 00004ff8:4",
			RowKey.BYTES, "Bytes: (KNOWN) 01 00 00 00",
			RowKey.INTEGER, "Integer: (KNOWN) 1",
			RowKey.VALUE, "Value: (KNOWN) 1h",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testRegisterReferenceHover() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		runToTallestRecursionAndCreateFrames(2);
		Instruction ins = program.getListing().getInstructionAt(registerRefInstr);
		HoverLocation loc = findOperandLocation(staticListing, ins, register("EDX"));
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: sum",
			RowKey.FRAME, "Frame: 0 fib pc=0040002c sp=00004ff4 base=00004ff4",
			RowKey.STORAGE, "Storage: EDX:4",
			RowKey.TYPE, "Type: uint",
			RowKey.LOCATION, "Location: EDX:4",
			RowKey.INTEGER, "Integer: (UNKNOWN) 0",
			RowKey.VALUE, "Value: (UNKNOWN) 0h",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testSavedRegisterReferenceHover() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		// need 3 frames. 0 has already popped EBP, so not saved. 1 will save on behalf of 2.
		Function function = runToTallestRecursionAndCreateFrames(3);
		traceManager.activateFrame(2);

		Instruction ins = program.getListing().getInstructionAt(function.getEntryPoint());
		HoverLocation loc = findOperandLocation(staticListing, ins, register("EBP"));
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: EBP",
			RowKey.FRAME, "Frame: 2 fib pc=00400013 sp=00004ff8 base=00005000",
			RowKey.LOCATION, "Location: 00004ff0:4",
			RowKey.INTEGER, "Integer: (KNOWN) 20476, 0x4ffc",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testRegisterReferenceInTraceHover() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		runToTallestRecursionAndCreateFrames(2);
		Instruction ins = copyToDynamic(program.getListing().getInstructionAt(registerRefInstr));
		// I guess the listing needs a moment???
		HoverLocation loc =
			waitForValue(() -> findOperandLocation(dynamicListing, ins, register("EDX")));
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: EDX",
			RowKey.INTEGER, "Integer: (UNKNOWN) 0",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	public static HoverLocation findTokenLocation(DecompilerPanel decompilerPanel,
			Function function, String tokText, String fieldText) {
		DecompileResults results = waitForValue(() -> {
			ProgramLocation pLoc = decompilerPanel.getCurrentLocation();
			if (!(pLoc instanceof DecompilerLocation dLoc)) {
				return null;
			}
			DecompileResults dr = dLoc.getDecompile();
			if (dr == null || dr.getFunction() != function) {
				return null;
			}
			return dr;
		});

		return runSwing(() -> {
			Program program = function.getProgram();
			ClangLayoutController layoutController = decompilerPanel.getLayoutController();
			BigInteger numIndexes = layoutController.getNumIndexes();
			for (BigInteger i = BigInteger.ZERO; i.compareTo(numIndexes) < 0; i =
				i.add(BigInteger.ONE)) {
				Layout layout = layoutController.getLayout(i);
				int numFields = layout.getNumFields();
				for (int j = 0; j < numFields; j++) {
					Field field = layout.getField(j);
					if (!(field instanceof ClangTextField clangField)) {
						continue;
					}
					if (!fieldText.equals(field.getText())) {
						continue;
					}
					int numRows = field.getNumRows();
					for (int r = 0; r < numRows; r++) {
						int numCols = field.getNumCols(r);
						for (int c = 0; c < numCols; c++) {
							FieldLocation fLoc = new FieldLocation(i, j, r, c);
							ClangToken token = clangField.getToken(fLoc);
							if (token != null && tokText.equals(token.getText())) {
								DecompilerLocation loc = token.getMinAddress() == null ? null
										: new DecompilerLocation(program, token.getMinAddress(),
											function.getEntryPoint(), results, token, i.intValue(),
											0);
								return new HoverLocation(loc, fLoc, field, token);
							}
						}
					}
				}
			}
			return null;
		});
	}

	protected HoverLocation findTokenLocation(Function function, String tokText, String fieldText) {
		tool.showComponentProvider(decompilerProvider, true);
		return findTokenLocation(decompilerPanel, function, tokText, fieldText);
	}

	@Test
	public void testGlobalHighVarHover() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		Function function = runToRetSetGlobalAndCreateFrames();
		HoverLocation loc = findTokenLocation(function, "myGlobal", "myGlobal = -0x21524111;");
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: myGlobal",
			RowKey.STORAGE, "Storage: 00600000:4",
			RowKey.TYPE, "Type: int",
			RowKey.LOCATION, "Location: 00600000:4",
			RowKey.BYTES, "Bytes: (KNOWN) ef be ad de",
			RowKey.INTEGER, """
					Integer: (KNOWN) 3735928559, 0xdeadbeef
					-559038737, -0x21524111""",
			RowKey.VALUE, "Value: (KNOWN) DEADBEEFh",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testStackHighVarHover() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		Function function = runToTallestRecursionAndCreateFrames(2);
		HoverLocation loc = findTokenLocation(function, "n", "if (1 < n) {");
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: n",
			RowKey.FRAME, "Frame: 0 fib pc=0040002c sp=00004ff4 base=00004ff4",
			RowKey.STORAGE, "Storage: Stack[0x4]:4",
			RowKey.TYPE, "Type: uint",
			RowKey.LOCATION, "Location: 00004ff8:4",
			RowKey.BYTES, "Bytes: (KNOWN) 01 00 00 00",
			RowKey.INTEGER, "Integer: (KNOWN) 1",
			RowKey.VALUE, "Value: (KNOWN) 1h",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testRegisterHighVarHover() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		Function function = runToTallestRecursionAndCreateFrames(2);
		// TODO: Line matching seems fragile
		HoverLocation loc = findTokenLocation(function, "uVar1", "uVar1 = fib(n - 1);");
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: uVar1",
			RowKey.FRAME, "Frame: 0 fib pc=0040002c sp=00004ff4 base=00004ff4",
			RowKey.STORAGE, "Storage: EAX:4",
			RowKey.TYPE, "Type: uint",
			RowKey.LOCATION, "Location: EAX:4",
			RowKey.INTEGER, "Integer: (KNOWN) 1",
			RowKey.VALUE, "Value: (KNOWN) 1h",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testStructureGlobalHighVarStruct() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		Function function = runToRetFillStructAndCreateFrames();
		goTo(staticListing, new ProgramLocation(program, function.getEntryPoint()));
		HoverLocation loc =
			findTokenLocation(function, "myGlobal", "return (uint)myStack.y + (uint)myGlobal.m;");
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: myGlobal",
			RowKey.STORAGE, "Storage: 00600000:4",
			RowKey.TYPE, "Type: MyStruct",
			RowKey.LOCATION, "Location: 00600000:4",
			RowKey.BYTES, "Bytes: (KNOWN) e6 07 0c 09",
			RowKey.INTEGER, "Integer: (KNOWN) 151783398, 0x90c07e6",
			RowKey.VALUE, "Value: (KNOWN) ",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testStructureGlobalHighVarStructField() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		Function function = runToRetFillStructAndCreateFrames();
		goTo(staticListing, new ProgramLocation(program, function.getEntryPoint()));
		HoverLocation loc =
			findTokenLocation(function, "m", "return (uint)myStack.y + (uint)myGlobal.m;");
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: m",
			RowKey.TYPE, "Type: byte",
			RowKey.LOCATION, "Location: 00600002:1",
			RowKey.BYTES, "Bytes: (KNOWN) 0c",
			RowKey.INTEGER, "Integer: (KNOWN) 12, 0xc",
			RowKey.VALUE, "Value: (KNOWN) Ch",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testStructureStackHighVarStruct() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		Function function = runToRetFillStructAndCreateFrames();
		goTo(staticListing, new ProgramLocation(program, function.getEntryPoint()));
		HoverLocation loc =
			findTokenLocation(function, "myStack", "return (uint)myStack.y + (uint)myGlobal.m;");
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: myStack",
			RowKey.FRAME, "Frame: 1 main pc=00400012 sp=00004fe4 base=00004ff0",
			RowKey.STORAGE, "Storage: Stack[-0x8]:4",
			RowKey.TYPE, "Type: MyStruct",
			RowKey.LOCATION, "Location: 00004fe8:4",
			RowKey.BYTES, "Bytes: (UNKNOWN) 00 00 00 00",
			RowKey.INTEGER, "Integer: (UNKNOWN) 0",
			RowKey.VALUE, "Value: (UNKNOWN) ",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testStructureStackHighVarStructField() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		Function function = runToRetFillStructAndCreateFrames();
		goTo(staticListing, new ProgramLocation(program, function.getEntryPoint()));
		HoverLocation loc =
			findTokenLocation(function, "y", "return (uint)myStack.y + (uint)myGlobal.m;");
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: y",
			RowKey.FRAME, "Frame: 1 main pc=00400012 sp=00004fe4 base=00004ff0",
			RowKey.TYPE, "Type: word",
			RowKey.LOCATION, "Location: 00004fe8:2",
			RowKey.BYTES, "Bytes: (UNKNOWN) 00 00",
			RowKey.INTEGER, "Integer: (UNKNOWN) 0",
			RowKey.VALUE, "Value: (UNKNOWN) 0h",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testStructurePointerRegisterHighVarStruct() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		runToRetFillStructAndCreateFrames();
		Function function = program.getFunctionManager().getFunctionContaining(retInstr);
		goTo(staticListing, new ProgramLocation(program, retInstr));
		HoverLocation loc = findTokenLocation(function, "s", "s->y = 0x7e6;");
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: s",
			RowKey.FRAME, "Frame: 0 fillStruct pc=00400041 sp=00004fe0 base=00004fe0",
			RowKey.STORAGE, "Storage: Stack[0x4]:4",
			RowKey.TYPE, "Type: MyStruct *",
			RowKey.LOCATION, "Location: 00004fe4:4",
			// NOTE: Value is the pointer, not the struct
			RowKey.BYTES, "Bytes: (KNOWN) 00 00 60 00",
			RowKey.INTEGER, "Integer: (KNOWN) 6291456, 0x600000",
			RowKey.VALUE, "Value: (KNOWN) 00600000",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testStructurePointerRegisterHighVarStructField() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		runToRetFillStructAndCreateFrames();
		Function function = program.getFunctionManager().getFunctionContaining(retInstr);
		goTo(staticListing, new ProgramLocation(program, retInstr));
		HoverLocation loc = findTokenLocation(function, "y", "s->y = 0x7e6;");
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: y",
			RowKey.FRAME, "Frame: 0 fillStruct pc=00400041 sp=00004fe0 base=00004fe0",
			RowKey.TYPE, "Type: word",
			RowKey.LOCATION, "Location: 00600000:2",
			RowKey.BYTES, "Bytes: (KNOWN) e6 07",
			RowKey.INTEGER, "Integer: (KNOWN) 2022, 0x7e6",
			RowKey.VALUE, "Value: (KNOWN) 7E6h",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	@Test
	public void testArrayGlobalHighVarIndexedField() throws Throwable {
		VariableValueHoverPlugin valuesPlugin = addPlugin(tool, VariableValueHoverPlugin.class);
		VariableValueHoverService valuesService = valuesPlugin.getHoverService();
		runToRetFillStructArrayAndCreateFrames();
		Function function = program.getFunctionManager().getFunctionContaining(retInstr);
		goTo(staticListing, new ProgramLocation(program, retInstr));
		HoverLocation loc = findTokenLocation(function, "m", "s[i].m = 0xc;");
		VariableValueTable table = getVariableValueTable(valuesService, loc.pLoc,
			traceManager.getCurrent(), loc.fLoc, loc.field);

		assertTable(Map.of(
			RowKey.NAME, "Name: m",
			RowKey.FRAME, "Frame: 0 fillStruct pc=0040002e sp=00004fe0 base=00004fe0",
			RowKey.TYPE, "Type: byte",
			RowKey.LOCATION, "Location: 0060000a:1",
			RowKey.BYTES, "Bytes: (KNOWN) 0c",
			RowKey.INTEGER, "Integer: (KNOWN) 12, 0xc",
			RowKey.VALUE, "Value: (KNOWN) Ch",
			RowKey.WARNINGS, "IGNORED"), table);
	}

	// @Test
	/**
	 * e.g., dstack._12_4_
	 */
	public void testOffcutPieceReference() throws Throwable {
		Unfinished.TODO();
	}

	// @Test
	public void testMultiVarnodeStorage() {
		Unfinished.TODO();
	}

	// @Test
	public void testWithPositiveGrowingStack() {
		Unfinished.TODO();
	}
}
