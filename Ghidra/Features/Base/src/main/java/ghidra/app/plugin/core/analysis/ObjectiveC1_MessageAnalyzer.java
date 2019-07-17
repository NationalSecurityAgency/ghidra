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

import java.util.List;

import ghidra.app.services.*;
import ghidra.app.util.bin.format.macho.SectionNames;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Constants;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Utilities;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class ObjectiveC1_MessageAnalyzer extends AbstractAnalyzer {
	private static final String DESCRIPTION =
			"An analyzer for extracting _objc_msgSend information.";

	private static final String NAME = "Objective-C Message";

	public ObjectiveC1_MessageAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(new AnalysisPriority(10000000));
	}

	/* ************************************************************************** */
	/* ************************************************************************** */

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		CurrentState state = new CurrentState(program);

		monitor.initialize(set.getNumAddresses());
		int progress = 0;

		AddressIterator iterator = set.getAddresses(true);
		while (iterator.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}

			monitor.setProgress(++progress);
			Address address = iterator.next();

			Function function = program.getListing().getFunctionAt(address);

			try {
				inspectFunction(program, function, state, monitor);
			}
			catch (Exception e) {
			}
		}

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return ObjectiveC1_Constants.isObjectiveC(program);
	}

	/* ************************************************************************** */
	/* ************************************************************************** */

	private void inspectFunction(Program program, Function function, CurrentState state,
			TaskMonitor monitor) {
		if (function == null) {
			return;
		}
		InstructionIterator instructionIterator =
				program.getListing().getInstructions(function.getBody(), true);
		while (instructionIterator.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}

			Instruction instruction = instructionIterator.next();

			if (isCallingObjcMsgSend(instruction)) {
				String eolComment = instruction.getComment(CodeUnit.EOL_COMMENT);

				if (eolComment != null) {//if a comment already exists, ignore...
					continue;
				}

				markupInstruction(instruction, state, monitor);
			}
		}
	}

	private boolean isCallingObjcMsgSend(Instruction instruction) {
		if (instruction.getNumOperands() != 1) {
			return false;
		}
		Reference reference = instruction.getPrimaryReference(0);
		if (reference == null) {
			return false;
		}
		if (!reference.getReferenceType().isCall() && !reference.getReferenceType().isJump()) {
			return false;
		}
		SymbolTable symbolTable = instruction.getProgram().getSymbolTable();
		Symbol symbol = symbolTable.getPrimarySymbol(reference.getToAddress());
		return isObjcNameMatch(symbol);
	}

	private boolean isObjcNameMatch(Symbol symbol) {
		String name = symbol.getName();
		return name.startsWith(ObjectiveC1_Constants.OBJC_MSG_SEND) ||
				name.equals(ObjectiveC1_Constants.READ_UNIX2003) ||
				name.startsWith("thunk" + ObjectiveC1_Constants.OBJC_MSG_SEND);
	}

	private class CurrentState {
		Program program;
		Namespace globalNamespace;
		Namespace selectorNamespace;
		Namespace idNamespace;

		String currentClassName = null;
		String currentMethodName = null;

		//Function currentFunction = null;

		CurrentState(Program program) {
			this.program = program;
			globalNamespace = program.getGlobalNamespace();
			SymbolTable symbolTable = program.getSymbolTable();
			selectorNamespace = findMatchingChildNamespace("@sel", globalNamespace, symbolTable);
			idNamespace = findMatchingChildNamespace("@id", globalNamespace, symbolTable);
		}

		boolean isValid() {
			return currentMethodName != null && currentClassName != null;
		}

		void reset() {
			currentClassName = null;
			currentMethodName = null;
		}

		@Override
		public String toString() {
			return "[" + currentClassName + " " + currentMethodName + "]";
		}

		private Namespace findMatchingChildNamespace(String namespaceName,
				Namespace parentNamespace, SymbolTable symbolTable) {
			SymbolIterator it = symbolTable.getSymbols(parentNamespace);
			while (it.hasNext()) {
				Symbol s = it.next();
				if (s.getSymbolType() == SymbolType.NAMESPACE) {
					if (namespaceName.equals(s.getName())) {
						return (Namespace) s.getObject();
					}
				}
			}
			try {
				return symbolTable.createNameSpace(parentNamespace, namespaceName,
					SourceType.ANALYSIS);
			}
			catch (DuplicateNameException e) {
			}
			catch (InvalidInputException e) {
			}
			return null;
		}
	}

	private void markupInstruction(Instruction instruction, CurrentState state,
			TaskMonitor monitor) {
		Address fromAddress = instruction.getMinAddress();
		Function function = state.program.getListing().getFunctionContaining(fromAddress);
		if (function == null) {
			return;
		}

		state.reset();
		InstructionIterator iter = state.program.getListing().getInstructions(fromAddress, false);
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}

			Instruction instructionBefore = iter.next();

			if (!function.getBody().contains(instructionBefore.getMinAddress())) {
				break;//don't look outside of the function
			}
			if (!isValidInstruction(instructionBefore)) {
				continue;
			}

			Reference[] opRefs = instructionBefore.getOperandReferences(1);
			if (opRefs.length != 1) {
				continue;
			}
			Address toAddress = opRefs[0].getToAddress();

			MemoryBlock block = state.program.getMemory().getBlock(toAddress);
			if (block == null) {
				continue;
			}

			pullNameThrough(state, toAddress, null);

			if (state.isValid()) {
				instruction.setComment(CodeUnit.EOL_COMMENT, state.toString());
				setReference(fromAddress, state);
				break;
			}
		}
	}

	// Tries to lay down a reference to the function that is actually being called
	private void setReference(Address fromAddress, CurrentState state) {
		SymbolTable symbolTable = state.program.getSymbolTable();
		Symbol classSymbol = symbolTable.getClassSymbol(state.currentClassName, (Namespace) null);
		if (classSymbol == null) {
			return;
		}
		Namespace namespace = (Namespace) classSymbol.getObject();
		List<Symbol> functionSymbols = symbolTable.getSymbols(state.currentMethodName, namespace);
		if (functionSymbols.size() >= 1) {
			Address toAddress = functionSymbols.get(0).getAddress();
			ReferenceManager referenceManager = state.program.getReferenceManager();
			Reference reference = referenceManager.addMemoryReference(fromAddress, toAddress,
				RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);
			referenceManager.setPrimary(reference, true);
		}
	}

	/**
	 * Objective-C class and method names are stored in the
	 * "__cstring" memory block. The strings are referenced
	 * by either the "class" block or the "message" block.
	 * The references are through n-levels of pointer indirection
	 * based on the specific target (x86 vs ppc vs arm).
	 * This method will pull the string through the pointer indirection
	 * and set the appropriate value in the current state.
	 */
	String pullNameThrough(CurrentState state, Address address, Namespace space) {
		MemoryBlock block = state.program.getMemory().getBlock(address);
		if (block == null) {
			return null;
		}
		if (block.getName().equals(SectionNames.TEXT_CSTRING)) {
			return ObjectiveC1_Utilities.createString(state.program, address);
		}
		Data data = state.program.getListing().getDataAt(address);
		if (data == null) {
			data = state.program.getListing().getDataContaining(address);
			if (data == null) {
				return null;
			}
			data = data.getComponentAt((int) address.subtract(data.getAddress()));
			if (data == null) {
				return null;
			}
		}
		Reference[] references = data.getValueReferences();
		if (references.length == 0) {
			return null;
		}
		if (address.equals(references[0].getToAddress())) {
			return null;//self reference
		}
		if (isClassBlock(block)) {
			space = state.idNamespace;
		}
		else if (isMessageBlock(block)) {
			space = state.selectorNamespace;
		}
		String name = pullNameThrough(state, references[0].getToAddress(), space);
		if (isClassBlock(block)) {
			if (state.currentClassName == null) {
				state.currentClassName = name;
			}
		}
		else if (isMessageBlock(block)) {
			if (state.currentMethodName == null) {
				state.currentMethodName = name;
			}
		}
		return name;
	}

	private boolean isMessageBlock(MemoryBlock block) {
		return block.getName().equals(ObjectiveC1_Constants.OBJC_SECTION_MESSAGE_REFS);
	}

	private boolean isClassBlock(MemoryBlock block) {
		return block.getName().equals(ObjectiveC1_Constants.OBJC_SECTION_CLASS_REFS) ||
				block.getName().equals(ObjectiveC1_Constants.OBJC_SECTION_CLASS);
	}

	private boolean isValidInstruction(Instruction instruction) {
		if (instruction.getNumOperands() != 2) {
			return false;
		}
		boolean isMOV = instruction.getMnemonicString().equals("MOV");//intel
		boolean isLWZ = instruction.getMnemonicString().equals("lwz");//powerpc
		boolean isLDR = instruction.getMnemonicString().equals("ldr");//arm
		return isMOV || isLWZ || isLDR;
	}
}
