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

import ghidra.app.services.*;
import ghidra.app.util.bin.format.macho.SectionNames;
import ghidra.app.util.bin.format.objc2.ObjectiveC2_Constants;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Constants;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ObjectiveC2_MessageAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Objective-C 2 Message";
	private static final String DESCRIPTION =
		"An analyzer for extracting Objective-C 2.0 message information.";

	/* ************************************************************************** */
	/* ************************************************************************** */

	public ObjectiveC2_MessageAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPrototype();
		//The Objective-C 2.0 analyzer should always run after the class analyzer.
		//It knows the deal!
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
	}

	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AddressIterator iterator = set.getAddresses(true);
		while (iterator.hasNext()) {
			Address address = iterator.next();

			Function function = program.getListing().getFunctionAt(address);

			try {
				inspectFunction(program, function, monitor);
			}
			catch (Exception e) {
				// ignore
			}
		}

		return true;
	}

	public boolean canAnalyze(Program program) {
		return ObjectiveC2_Constants.isObjectiveC2(program);
	}

	/* ************************************************************************** */
	/* ************************************************************************** */

	private void inspectFunction(Program program, Function function, TaskMonitor monitor) {
		if (function == null) {
			return;
		}

		InstructionIterator instructionIterator =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructionIterator.hasNext()) {
			Instruction instruction = instructionIterator.next();

			if (isCallingObjcMsgSend(instruction)) {
				String eolComment = instruction.getComment(CodeUnit.EOL_COMMENT);

				if (eolComment != null) {//if a comment already exists, ignore...
					continue;
				}

				markupInstruction(program, instruction, monitor);
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
			name.equals(ObjectiveC1_Constants.READ_UNIX2003);
	}

	private void markupInstruction(Program program, Instruction instruction, TaskMonitor monitor) {
		Address fromAddress = instruction.getMinAddress();
		Function function = program.getListing().getFunctionContaining(fromAddress);
		if (function == null) {
			return;
		}

		String currentClass = null;
		String currentMethod = null;

		InstructionIterator iter = program.getListing().getInstructions(fromAddress, false);
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			Instruction instructionBefore = iter.next();

			if (!function.getBody().contains(instructionBefore.getMinAddress())) {
				break;//don't look outside of the function
			}

			final String CLASS_REGISTER = "r0";
			final String METHOD_REGISTER = "r1";

			boolean isRegisterModified = false;

			if (isRegisterModified(instructionBefore, CLASS_REGISTER)) {
				currentClass = null;
				isRegisterModified = true;
			}

			if (isRegisterModified(instructionBefore, METHOD_REGISTER)) {
				currentClass = null;
				isRegisterModified = true;
			}

			if (!isValidInstruction(instructionBefore)) {
				if (isRegisterModified) {
					break;
				}
				continue;
			}

			Object[] firstOperandObjects = instructionBefore.getOpObjects(0);
			if (firstOperandObjects.length != 1) {
				continue;
			}
			if (!(firstOperandObjects[0] instanceof Register)) {
				continue;
			}
			Register register = (Register) firstOperandObjects[0];

			if (!register.getName().equals(CLASS_REGISTER) &&
				!register.getName().equals(METHOD_REGISTER)) {
				continue;
			}

			Object[] secondOperandObjects = instructionBefore.getOpObjects(1);
			if (secondOperandObjects.length != 1) {
				continue;
			}

			if (!(secondOperandObjects[0] instanceof Address)) {
				continue;
			}
			Address toAddress = (Address) secondOperandObjects[0];

			MemoryBlock block = program.getMemory().getBlock(toAddress);
			if (block == null) {
				continue;
			}

			if (register.getName().equals(CLASS_REGISTER)) {
				currentClass = getClassName(program, toAddress);
			}
			else if (register.getName().equals(METHOD_REGISTER)) {
				currentMethod = getMethodName(program, toAddress);
			}

			if (currentClass != null && currentMethod != null) {
				instruction.setComment(CodeUnit.EOL_COMMENT, "[" + currentClass + " " +
					currentMethod + "]");
				break;
			}
		}
	}

	private boolean isRegisterModified(Instruction instruction, String registerName) {
		Object[] destinationOperandObjects = instruction.getOpObjects(0);
		if (destinationOperandObjects.length != 1) {
			return false;
		}
		if (!(destinationOperandObjects[0] instanceof Register)) {
			return false;
		}
		Register register = (Register) destinationOperandObjects[0];
		if (register.getName().equals(registerName)) {
			return true;
		}
		return false;
	}

	private String getClassName(Program program, Address toAddress) {
		try {
			int classPointerValue = program.getMemory().getInt(toAddress);
			Address classPointerAddress = toAddress.getNewAddress(classPointerValue);

			if (!isObjcClassRefBlock(program, classPointerAddress)) {
				return null;
			}

			Data classPointerData = program.getListing().getDefinedDataAt(classPointerAddress);

			Address classAddress = (Address) classPointerData.getValue();

			if (!isObjcDataBlock(program, classAddress)) {
				return null;
			}

			Data classData = program.getListing().getDefinedDataAt(classAddress);

			Data classRwPointerData = classData.getComponent(4);
			Address classRwPointerAddress = (Address) classRwPointerData.getValue();

			if (!isObjcConstBlock(program, classRwPointerAddress)) {
				return null;
			}

			Data classRwData = program.getListing().getDefinedDataAt(classRwPointerAddress);
			Data classNamePointerData = classRwData.getComponent(4);

			Address classNameAddress = (Address) classNamePointerData.getValue();

			if (!isCStringBlock(program, classNameAddress)) {
				return null;
			}

			Data classNameData = program.getListing().getDefinedDataAt(classNameAddress);
			String className = (String) classNameData.getValue();
			return className;
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private String getMethodName(Program program, Address toAddress) {
		try {
			int methodNamePointerValue = program.getMemory().getInt(toAddress);
			Address methodNamePointerAddress = toAddress.getNewAddress(methodNamePointerValue);

			if (!isObjcSelectorRefBlock(program, methodNamePointerAddress)) {
				return null;
			}

			Data methodNamePointerData =
				program.getListing().getDefinedDataAt(methodNamePointerAddress);

			Address methodNameAddress = (Address) methodNamePointerData.getValue();

			if (!isCStringBlock(program, methodNameAddress)) {
				return null;
			}

			Data methodNameData = program.getListing().getDefinedDataAt(methodNameAddress);
			String methodName = (String) methodNameData.getValue();
			return methodName;
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return null;
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

	private boolean isCStringBlock(Program program, Address address) {
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block != null) {
			if (block.getName().equals(SectionNames.TEXT_CSTRING)) {
				return true;
			}
		}
		return false;
	}

	private boolean isObjcSelectorRefBlock(Program program, Address address) {
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block != null) {
			if (block.getName().equals(ObjectiveC2_Constants.OBJC2_SELECTOR_REFS)) {
				return true;
			}
		}
		return false;
	}

	private boolean isObjcClassRefBlock(Program program, Address address) {
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block != null) {
			if (block.getName().equals(ObjectiveC2_Constants.OBJC2_CLASS_REFS)) {
				return true;
			}
		}
		return false;
	}

	private boolean isObjcConstBlock(Program program, Address address) {
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block != null) {
			if (block.getName().equals(ObjectiveC2_Constants.OBJC2_CONST)) {
				return true;
			}
		}
		return false;
	}

	private boolean isObjcDataBlock(Program program, Address address) {
		MemoryBlock block = program.getMemory().getBlock(address);
		if (block != null) {
			if (block.getName().equals(ObjectiveC2_Constants.OBJC2_DATA)) {
				return true;
			}
		}
		return false;
	}
}
