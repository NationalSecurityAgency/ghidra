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

import java.io.IOException;
import java.util.function.Predicate;

import ghidra.app.services.*;
import ghidra.app.util.bin.format.golang.GoParamStorageAllocator;
import ghidra.app.util.bin.format.golang.rtti.*;
import ghidra.app.util.bin.format.golang.structmapping.MarkupSession;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.UnknownProgressWrappingTaskMonitor;

/**
 * Analyzer that finds Golang strings (and optionally slices) and marks up the found instances.
 * <p>
 * The char[] data for Golang strings does not contain null terminators, so the normal logic already
 * built into Ghidra to find terminated strings doesn't work.
 * <p>
 * This implementation looks for data that matches what a Golang string 
 * struct { char* data, long len } would look like, and follows the pointer to the char[] data 
 * and creates a fixed-length string at that location using the length info from the struct.
 * <p>
 * The string struct is found in a couple of different ways:
 * <ul>
 * 	<li>References from an instruction (see markupStaticStructRefsInFunction)
 *  <li>Iterating through data segments and making educated guesses (see markupDataSegmentStructs)
 * </ul>
 * Some char[] data is only referenced from Golang string structs that exist temporarily
 * in registers after being set by an instruction that statically references the char[] data,
 * and an instruction that statically contains the length. (see tryCreateInlineString) 
 * <p>
 * Because slice structures can look like string structs, possible string struct locations are also
 * examined for slice-ness.  When marking a struct as a slice instead of as a string, the data
 * pointed to by the slice is not marked up because there is no information about the size of the
 * elements that the slice points to.
 */
public class GolangStringAnalyzer extends AbstractAnalyzer {
	private final static String NAME = "Golang String Analyzer";
	private final static String DESCRIPTION =
		"Finds and labels Go string structures that have been referenced from a function.";

	private GolangStringAnalyzerOptions analyzerOptions = new GolangStringAnalyzerOptions();
	private GoRttiMapper goBinary;
	private MarkupSession markupSession;
	private GoParamStorageAllocator storageAllocator;

	public GolangStringAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public void registerOptions(Options options, Program program_notused) {
		analyzerOptions.registerOptions(options);
	}

	@Override
	public void optionsChanged(Options options, Program program_notused) {
		analyzerOptions.optionsChanged(options);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return GoRttiMapper.isGolangProgram(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		goBinary = GoRttiMapper.getSharedGoBinary(program, monitor);
		if (goBinary == null) {
			Msg.error(this, "Golang analyzer error: unable to get GoRttiMapper");
			return false;
		}
		markupSession = goBinary.createMarkupSession(monitor);
		storageAllocator = goBinary.newStorageAllocator();

		try {
			goBinary.initTypeInfoIfNeeded(monitor);

			markupStaticStructRefsInFunctions(set, monitor);

			if (analyzerOptions.markupDataSegmentStructs) {
				markupDataSegmentStructs(monitor);
			}
		}
		catch (IOException e) {
			Msg.error(this, "Golang analysis failure", e);
		}

		return true;
	}

	private static boolean alignStartOfSet(AddressSet set, int align) {
		while (!set.isEmpty()) {
			Address addr = set.getMinAddress();
			int mod = (int) (addr.getOffset() % align);
			if (mod == 0) {
				return true;
			}
			AddressRange range = set.getFirstRange();
			addr = addr.add(align - mod - 1);
			set.deleteFromMin(range.contains(addr) ? addr : range.getMaxAddress());
		}
		return false;
	}

	private void markupStaticStructRefsInFunctions(AddressSetView set, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor = new UnknownProgressWrappingTaskMonitor(monitor);
		monitor.initialize(1, "Searching for Golang structure references in functions");

		FunctionManager funcManager = goBinary.getProgram().getFunctionManager();

		for (Function function : funcManager.getFunctions(set, true)) {
			monitor.checkCancelled();
			markupStaticStructRefsInFunction(function, monitor);
		}
	}

	private void markupStaticStructRefsInFunction(Function function, TaskMonitor monitor)
			throws IOException, CancelledException {

		ReferenceManager refManager = goBinary.getProgram().getReferenceManager();
		Listing listing = goBinary.getProgram().getListing();

		AddressSet stringDataRange = new AddressSet(goBinary.getStringDataRange());
		AddressSetView validStructRange = goBinary.getStringStructRange();
		AddressSetView funcBody = function.getBody();
		for (Reference ref : refManager.getReferenceIterator(function.getEntryPoint())) {
			monitor.increment();
			if (!funcBody.contains(ref.getFromAddress())) {
				// limit the reference iterator to the function body
				break;
			}
			Address addr = ref.getToAddress();

			if (ref.getReferenceType() != RefType.DATA) {
				continue;
			}
			if (validStructRange.contains(addr) && canCreateStructAt(addr)) {
				if (tryCreateStruct(stringDataRange, addr) != null) {
					continue;
				}
				if (!stringDataRange.contains(addr)) {
					continue;
				}

				Instruction instr = listing.getInstructionContaining(ref.getFromAddress());
				GoString inlineStr = tryCreateInlineString(funcBody, stringDataRange, addr, instr,
					this::isValidStringData);
				if (inlineStr != null) {
					// just markup the char data, there is no struct body
					inlineStr.additionalMarkup(markupSession);
				}
			}
		}
	}

	private GoString tryCreateInlineString(AddressSetView funcBody, AddressSet stringDataRange,
			Address stringDataAddr, Instruction instr1, Predicate<String> stringContentValidator) {
		// Precondition: instr1 has a ref to a location that could be the chars of a 
		// string (stringDataAddr).
		// The logic matches on 2 consecutive instructions that load 2 consecutive go param 
		// storage allocator registers (ex AX, then BX), because we know that a go string struct 
		// can fit into 2 registers when passed to a function
		// This needs to be improved to handle initializing a stack parameter.

		Instruction instr2 = instr1.getNext();
		if (instr2 == null || !funcBody.contains(instr2.getAddress())) {
			return null;
		}

		Register strAddrReg = getRegisterFromInstr(instr1);
		Register strLenReg = storageAllocator.getNextIntParamRegister(strAddrReg);
		if (strLenReg != null && strLenReg.contains(getRegisterFromInstr(instr2))) {
			// the first register was from the set of param passing registers, and we now know
			// what the second register must be to match the pattern
			long strLen = getScalarFromInstr(instr2);
			try {
				GoString str = GoString.createInlineString(goBinary, stringDataAddr, strLen);
				if (str.isValidInlineString(stringDataRange, stringContentValidator)) {
					return str;
				}
			}
			catch (IOException e) {
				// fail
			}
		}
		return null;
	}

	private Register getRegisterFromInstr(Instruction instr) {
		if (instr.getNumOperands() != 2 || instr.getOperandType(0) != OperandType.REGISTER) {
			return null;
		}
		return (Register) instr.getOpObjects(0)[0];
	}

	private long getScalarFromInstr(Instruction instr) {
		if (instr.getNumOperands() != 2) {
			return -1;
		}
		Object operand1Obj0 = instr.getOpObjects(1)[0];
		return instr.getOperandType(1) == OperandType.SCALAR && operand1Obj0 instanceof Scalar s
				? s.getUnsignedValue()
				: -1;
	}

	private void markupDataSegmentStructs(TaskMonitor monitor)
			throws IOException, CancelledException {

		AddressSet structDataRange = new AddressSet(goBinary.getStringStructRange());
		structDataRange.delete(markupSession.getMarkedupAddresses());

		AddressSet stringDataRange = new AddressSet(goBinary.getStringDataRange());

		long initAddrCount = structDataRange.getNumAddresses();
		monitor.initialize(initAddrCount,
			"Searching for Golang strings & structures in data segments");

		int stringCount = 0;
		int sliceCount = 0;

		int align = goBinary.getPtrSize();
		while (alignStartOfSet(structDataRange, align)) {
			monitor.setProgress(initAddrCount - structDataRange.getNumAddresses());
			monitor.checkCancelled();

			Address addr = structDataRange.getMinAddress();
			if (!canCreateStructAt(addr)) {
				Data data = goBinary.getProgram().getListing().getDataContaining(addr);
				if (data != null) {
					structDataRange.deleteFromMin(data.getMaxAddress());
				}
				continue;
			}

			structDataRange.deleteFromMin(addr);

			Object newObj = tryCreateStruct(stringDataRange, addr);
			if (newObj != null) {
				structDataRange.deleteFromMin(goBinary.getMaxAddressOfStructure(newObj));
				stringCount += newObj instanceof GoString ? 1 : 0;
				sliceCount += newObj instanceof GoSlice ? 1 : 0;
				monitor.setMessage("Searching for Golang strings & slices in data segments: %d+%d"
						.formatted(stringCount, sliceCount));
			}
		}
	}

	private Object tryCreateStruct(AddressSet stringDataRange, Address addr)
			throws IOException, CancelledException {
		// test to see if its a slice first because strings can kinda look like slices (a pointer
		// then a length field).
		Object newObj = tryReadSliceStruct(addr);
		if (newObj == null) {
			newObj = tryReadStringStruct(stringDataRange, addr);
		}
		if (newObj != null) {
			boolean doMarkup = analyzerOptions.markupSliceStructs || !(newObj instanceof GoSlice);
			if (doMarkup) {
				markupSession.markup(newObj, false);
				if (newObj instanceof GoString goStr) {
					stringDataRange.delete(goStr.getStringDataRange());
				}
			}
		}
		return newObj;
	}

	private GoString tryReadStringStruct(AddressSetView stringDataRange, Address addr) {
		try {
			GoString goString = goBinary.readStructure(GoString.class, addr);
			if (goString.isValid(stringDataRange, this::isValidStringData)) {
				return goString;
			}
		}
		catch (IOException e) {
			// ignore, skip
		}
		return null;
	}

	private boolean isValidStringData(String s) {
		// naive test that ensures that the candidate string doesn't have 'garbage' characters
		// TODO: this should be wired into the string model logic
		return (s != null) && !s.codePoints().anyMatch(this::isBadCodePoint);
	}

	private boolean isBadCodePoint(int codePoint) {
		return codePoint == StringUtilities.UNICODE_REPLACEMENT ||
			(0 <= codePoint && codePoint < 32) && !(codePoint == '\n' || codePoint == '\t');
	}

	private GoSlice tryReadSliceStruct(Address addr) {
		try {
			GoSlice slice = goBinary.readStructure(GoSlice.class, addr);
			if (slice.getLen() != 0 && slice.isFull() && slice.isValid()) {
				return slice;
			}
		}
		catch (IOException e) {
			// ignore, skip
		}
		return null;
	}

	private boolean canCreateStructAt(Address addr) {
		Data data = goBinary.getProgram().getListing().getDataContaining(addr);
		return data == null || !data.isDefined() || Undefined.isUndefined(data.getDataType()) ||
			(data.getDataType() instanceof Pointer ptr && ptr.getDataType() == null);
	}

	//-------------------------------------------------------------------------------------------
	private static class GolangStringAnalyzerOptions {
		static final String MARKUP_SLICES_OPTIONNAME = "Markup slices";
		static final String MARKUP_SLICES_DESC = "Markup things that look like slices.";

		static final String MARKUP_STRUCTS_IN_DATA_OPTIONNAME = "Search data segments";
		static final String MARKUP_STRUCTS_IN_DATA_DESC =
			"Search for strings and slices in data segments.";

		boolean markupSliceStructs = true;
		boolean markupDataSegmentStructs = true;

		void registerOptions(Options options) {
			options.registerOption(GolangStringAnalyzerOptions.MARKUP_SLICES_OPTIONNAME,
				markupSliceStructs, null, GolangStringAnalyzerOptions.MARKUP_SLICES_DESC);
			options.registerOption(GolangStringAnalyzerOptions.MARKUP_STRUCTS_IN_DATA_OPTIONNAME,
				markupDataSegmentStructs, null,
				GolangStringAnalyzerOptions.MARKUP_STRUCTS_IN_DATA_DESC);
		}

		void optionsChanged(Options options) {
			markupDataSegmentStructs =
				options.getBoolean(GolangStringAnalyzerOptions.MARKUP_STRUCTS_IN_DATA_OPTIONNAME,
					markupDataSegmentStructs);
			markupSliceStructs = options.getBoolean(
				GolangStringAnalyzerOptions.MARKUP_SLICES_OPTIONNAME, markupSliceStructs);

		}

	}

}
