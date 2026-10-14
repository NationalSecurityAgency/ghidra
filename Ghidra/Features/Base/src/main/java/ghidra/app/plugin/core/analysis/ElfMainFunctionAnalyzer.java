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

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ElfMainFunctionAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "ELF x86-64 Main Function";
	private static final String DESCRIPTION =
		"Creates a main function at the first argument of the __libc_start_main call in the ELF " +
			"entry point.";

	private static final String LIBC_START_MAIN_NAME = "__libc_start_main";
	private static final String MAIN_NAME = "main";
	private static final String ENTRY_FIELD_NAME = "e_entry";
	private static final String FIRST_ARGUMENT_REGISTER = "RDI";
	private static final String PROCESSOR_NAME = "x86";
	private static final int ADDRESS_SIZE = 64;
	private static final int MAX_ENTRY_INSTRUCTIONS = 40;

	public ElfMainFunctionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!ElfLoader.ELF_NAME.equals(program.getExecutableFormat())) {
			return false;
		}
		Language language = program.getLanguage();
		if (language.getDefaultSpace().getSize() != ADDRESS_SIZE) {
			return false;
		}
		if (!language.getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME))) {
			return false;
		}
		return program.getRegister(FIRST_ARGUMENT_REGISTER) != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Function entryFunction = getEntryFunction(program);
		if (entryFunction == null) {
			return false;
		}
		Instruction call = findLibcStartMainCall(program, entryFunction, monitor);
		if (call == null) {
			return false;
		}
		Address mainAddress = findFirstArgumentTarget(program, entryFunction, call, monitor);
		if (mainAddress == null) {
			return false;
		}
		if (program.getFunctionManager().getFunctionAt(mainAddress) != null) {
			return false;
		}
		Symbol existing = program.getSymbolTable().getPrimarySymbol(mainAddress);
		if (existing != null && existing.getSource() != SourceType.DEFAULT) {
			return false;
		}

		CreateFunctionCmd command =
			new CreateFunctionCmd(MAIN_NAME, mainAddress, null, SourceType.ANALYSIS);
		if (!command.applyTo(program, monitor)) {
			log.appendMsg(getName(), "Could not create " + MAIN_NAME + " at " + mainAddress + ": " +
				command.getStatusMsg());
			return false;
		}
		return true;
	}

	/**
	 * Locates the function at e_entry by following the reference the ELF loader records from the
	 * e_entry field of the header. The reference is used rather than the field value because for a
	 * position independent executable the stored value is file relative while the reference target
	 * is the loaded address.
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
				if (reference.getSource() == SourceType.IMPORTED) {
					return program.getFunctionManager().getFunctionAt(reference.getToAddress());
				}
			}
			return null;
		}
		return null;
	}

	private Instruction findLibcStartMainCall(Program program, Function entryFunction,
			TaskMonitor monitor) throws CancelledException {

		Instruction instruction =
			program.getListing().getInstructionAt(entryFunction.getEntryPoint());
		for (int i = 0; instruction != null && i < MAX_ENTRY_INSTRUCTIONS; i++) {
			monitor.checkCancelled();
			if (!entryFunction.getBody().contains(instruction.getAddress())) {
				return null;
			}
			if (instruction.getFlowType().isCall() && callsLibcStartMain(program, instruction)) {
				return instruction;
			}
			instruction = instruction.getNext();
		}
		return null;
	}

	private boolean callsLibcStartMain(Program program, Instruction instruction) {
		for (Reference reference : instruction.getReferencesFrom()) {
			if (!reference.getReferenceType().isCall()) {
				continue;
			}
			Function callee = program.getFunctionManager().getFunctionAt(reference.getToAddress());
			if (callee == null) {
				continue;
			}
			Function thunked = callee.getThunkedFunction(true);
			Function target = thunked != null ? thunked : callee;
			if (LIBC_START_MAIN_NAME.equals(target.getName())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Walks back from the call to the last instruction that writes the first argument register,
	 * staying within one straight line run so that a write on another path is not mistaken for the
	 * argument. The instruction is chosen by the register it writes, never by reference type,
	 * because a position independent executable reaches the register through a LEA carrying a DATA
	 * reference while a position dependent one uses a MOV carrying a PARAM reference.
	 */
	private Address findFirstArgumentTarget(Program program, Function entryFunction,
			Instruction call, TaskMonitor monitor) throws CancelledException {

		Register argument = program.getRegister(FIRST_ARGUMENT_REGISTER);
		Instruction later = call;
		Instruction earlier = call.getPrevious();
		for (int i = 0; earlier != null && i < MAX_ENTRY_INSTRUCTIONS; i++) {
			monitor.checkCancelled();
			if (!entryFunction.getBody().contains(earlier.getAddress())) {
				return null;
			}
			if (!later.getAddress().equals(earlier.getFallThrough())) {
				return null;
			}
			if (writesRegister(earlier, argument)) {
				return getExecutableTarget(program, earlier);
			}
			later = earlier;
			earlier = earlier.getPrevious();
		}
		return null;
	}

	private boolean writesRegister(Instruction instruction, Register register) {
		for (Object result : instruction.getResultObjects()) {
			if (register.equals(result)) {
				return true;
			}
		}
		return false;
	}

	private Address getExecutableTarget(Program program, Instruction instruction) {
		for (Reference reference : instruction.getReferencesFrom()) {
			Address target = reference.getToAddress();
			MemoryBlock block = program.getMemory().getBlock(target);
			if (block != null && block.isInitialized() && block.isExecute()) {
				return target;
			}
		}
		return null;
	}
}
