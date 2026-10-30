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

import java.util.Iterator;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.UnknownContextException;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class ElfMainFunctionAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ELF Main Function";
	private static final String DESCRIPTION =
		"Creates a main function at the first argument of the __libc_start_main call in the ELF " +
			"entry point.";

	private static final String OPTION_NAME_DECOMPILER_TIMEOUT_SECS =
		"Analysis Decompiler Timeout (sec)";
	private static final String OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS =
		"Set timeout in seconds for analyzer decompiler calls.";
	public static final int OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS = 60;

	private static final String LIBC_START_MAIN_NAME = "__libc_start_main";
	private static final String MAIN_NAME = "main";
	private static final String ENTRY_FIELD_NAME = "e_entry";
	private static final int MAX_LEADING_NO_PCODE_INSTRUCTIONS = 4;
	private static final int MAX_STUB_DISTANCE = 16;

	private int decompilerTimeoutSecondsOption = OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS;

	public ElfMainFunctionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.CODE_ANALYSIS);
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return ElfLoader.ELF_NAME.equals(program.getExecutableFormat());
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_DECOMPILER_TIMEOUT_SECS, decompilerTimeoutSecondsOption,
			null, OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		decompilerTimeoutSecondsOption =
			options.getInt(OPTION_NAME_DECOMPILER_TIMEOUT_SECS, decompilerTimeoutSecondsOption);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		if (program.getSymbolTable().getSymbolIterator(MAIN_NAME, true).hasNext()) {
			return false;
		}
		Function entryFunction = getEntryFunction(program);
		if (entryFunction == null) {
			return false;
		}
		if (!callsLibcStartMain(program, entryFunction, monitor)) {
			return false;
		}
		Address mainAddress = findMainAddress(program, entryFunction, monitor);
		if (mainAddress == null) {
			return false;
		}
		return applyMain(program, mainAddress, monitor, log);
	}

	/**
	 * Locates the function at e_entry by following the reference the ELF loader records from the
	 * e_entry field of the header. The reference is used rather than the field value because for a
	 * position independent executable the stored value is file relative while the reference target
	 * is the loaded address. The target is normalized because a pointer to Thumb code carries the
	 * low bit set while the function is created on the even address.
	 */
	private Function getEntryFunction(Program program) {
		Data header = program.getListing().getDefinedDataAt(program.getImageBase());
		if (header == null) {
			return null;
		}
		for (int i = 0; i < header.getNumComponents(); i++) {
			Data component = header.getComponent(i);
			if (component == null || !ENTRY_FIELD_NAME.equals(component.getFieldName())) {
				continue;
			}
			for (Reference reference : component.getReferencesFrom()) {
				if (reference.getSource() != SourceType.IMPORTED) {
					continue;
				}
				Address entry = PseudoDisassembler.getNormalizedDisassemblyAddress(program,
					reference.getToAddress());
				return program.getFunctionManager().getFunctionAt(entry);
			}
			return null;
		}
		return null;
	}

	/**
	 * Checks the listing for the call before the decompiler is started, so that a program whose
	 * entry point does not reach __libc_start_main never pays for a decompiler process.
	 */
	private boolean callsLibcStartMain(Program program, Function entryFunction, TaskMonitor monitor)
			throws CancelledException {

		for (Instruction instruction : program.getListing()
				.getInstructions(entryFunction.getBody(), true)) {
			monitor.checkCancelled();
			if (!instruction.getFlowType().isCall()) {
				continue;
			}
			for (Reference reference : instruction.getReferencesFrom()) {
				if (!reference.getReferenceType().isCall()) {
					continue;
				}
				Function callee =
					program.getFunctionManager().getFunctionAt(reference.getToAddress());
				if (callee != null && LIBC_START_MAIN_NAME.equals(callee.getName())) {
					return true;
				}
			}
		}
		return false;
	}

	private Address findMainAddress(Program program, Function entryFunction, TaskMonitor monitor)
			throws CancelledException {

		DecompInterface decompiler = new DecompInterface();
		try {
			DecompileOptions options = new DecompileOptions();
			options.grabFromProgram(program);
			decompiler.toggleCCode(false);
			decompiler.toggleSyntaxTree(true);
			decompiler.setSimplificationStyle("decompile");
			decompiler.setOptions(options);
			if (!decompiler.openProgram(program)) {
				return null;
			}
			DecompileResults results = decompiler.decompileFunction(entryFunction,
				decompilerTimeoutSecondsOption, monitor);
			if (!results.decompileCompleted()) {
				return null;
			}
			PcodeOpAST call = findLibcStartMainCall(program, results.getHighFunction(), monitor);
			if (call == null) {
				return null;
			}
			return resolveArgument(program, entryFunction, call);
		}
		finally {
			decompiler.closeProgram();
			decompiler.dispose();
		}
	}

	private PcodeOpAST findLibcStartMainCall(Program program, HighFunction highFunction,
			TaskMonitor monitor) throws CancelledException {

		if (highFunction == null) {
			return null;
		}
		Iterator<PcodeOpAST> operations = highFunction.getPcodeOps();
		while (operations.hasNext()) {
			monitor.checkCancelled();
			PcodeOpAST operation = operations.next();
			if (operation.getOpcode() != PcodeOp.CALL) {
				continue;
			}
			Varnode target = operation.getInput(0);
			if (target == null || !target.isAddress()) {
				continue;
			}
			Function callee = program.getFunctionManager().getFunctionAt(target.getAddress());
			if (callee != null && LIBC_START_MAIN_NAME.equals(callee.getName())) {
				return operation;
			}
		}
		return null;
	}

	/**
	 * Takes the first argument of the call, which the decompiler presents as a pointer to the
	 * image rather than as a plain constant.
	 */
	private Address resolveArgument(Program program, Function entryFunction, PcodeOpAST call) {
		if (call.getNumInputs() < 2) {
			return null;
		}
		PcodeOp definition = call.getInput(1).getDef();
		if (definition == null || definition.getOpcode() != PcodeOp.PTRSUB ||
			definition.getNumInputs() != 2) {
			return null;
		}
		Varnode base = definition.getInput(0);
		Varnode offset = definition.getInput(1);
		if (!base.isConstant() || base.getOffset() != 0 || !offset.isConstant()) {
			return null;
		}
		Address argument =
			program.getAddressFactory().getDefaultAddressSpace().getAddress(offset.getOffset());
		if (!isInExecutableBlock(program, argument)) {
			return null;
		}
		Address stub = followBranchStub(program, entryFunction, argument);
		if (stub != null) {
			if (!isInExecutableBlock(program, stub)) {
				return null;
			}
			argument = stub;
		}
		return PseudoDisassembler.setTargetContextForDisassembly(program, argument);
	}

	/**
	 * Follows a single branch only when the target sits just past the end of the entry function,
	 * which is where glibc places the file local __wrap_main label in start.S. A main that is
	 * itself one branch to another function is identical in content, so only location separates
	 * them.
	 */
	private Address followBranchStub(Program program, Function entryFunction, Address argument) {
		long distance =
			argument.getOffset() - entryFunction.getBody().getMaxAddress().getOffset() - 1;
		if (distance < 0 || distance > MAX_STUB_DISTANCE) {
			return null;
		}
		PseudoDisassembler disassembler = new PseudoDisassembler(program);
		PseudoDisassemblerContext context =
			new PseudoDisassemblerContext(program.getProgramContext());
		Address current = argument;
		for (int i = 0; i <= MAX_LEADING_NO_PCODE_INSTRUCTIONS; i++) {
			PseudoInstruction instruction;
			try {
				instruction = disassembler.disassemble(current, context, false);
			}
			catch (InsufficientBytesException | UnknownInstructionException
					| UnknownContextException e) {
				return null;
			}
			if (instruction == null) {
				return null;
			}
			if (instruction.getPcode().length != 0) {
				if (!instruction.getFlowType().isJump() ||
					instruction.getFlowType().isConditional()) {
					return null;
				}
				Address[] flows = instruction.getFlows();
				return flows.length == 1 ? flows[0] : null;
			}
			current = current.add(instruction.getLength());
		}
		return null;
	}

	private boolean isInExecutableBlock(Program program, Address address) {
		MemoryBlock block = program.getMemory().getBlock(address);
		return block != null && block.isInitialized() && block.isExecute();
	}

	private boolean applyMain(Program program, Address mainAddress, TaskMonitor monitor,
			MessageLog log) {

		Function existing = program.getFunctionManager().getFunctionAt(mainAddress);
		if (existing != null) {
			return renameToMain(existing, log);
		}
		Symbol primary = program.getSymbolTable().getPrimarySymbol(mainAddress);
		if (primary != null && primary.getSource() != SourceType.DEFAULT) {
			return false;
		}
		CreateFunctionCmd command =
			new CreateFunctionCmd(MAIN_NAME, mainAddress, null, SourceType.ANALYSIS);
		if (!command.applyTo(program, monitor)) {
			log.appendMsg(getName(), "Could not create " + MAIN_NAME + " at " + mainAddress + ": " +
				command.getStatusMsg());
			return false;
		}
		Function created = program.getFunctionManager().getFunctionAt(mainAddress);
		if (MAIN_NAME.equals(created.getName())) {
			return true;
		}
		// A main that is a single branch to another function is created as a thunk, and a thunk
		// takes its name from the label at its entry rather than from the requested name.
		return renameToMain(created, log);
	}

	private boolean renameToMain(Function function, MessageLog log) {
		if (function.getSymbol().getSource() != SourceType.DEFAULT) {
			return false;
		}
		try {
			function.setName(MAIN_NAME, SourceType.ANALYSIS);
		}
		catch (DuplicateNameException | InvalidInputException e) {
			log.appendMsg(getName(), "Could not rename the function at " +
				function.getEntryPoint() + " to " + MAIN_NAME + ": " + e.getMessage());
			return false;
		}
		return true;
	}
}
