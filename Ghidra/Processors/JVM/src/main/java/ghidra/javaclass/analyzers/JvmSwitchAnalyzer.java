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
package ghidra.javaclass.analyzers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.javaclass.format.JavaClassUtil;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 *  This analyzer reads through JVM .class files looking for lookupswitch and tableswitch instructions.
 *  For each such instruction, the analyzer determines all the possible jump targets, disassembles them,
 *  and then newly-disassembled code to the appropriate function body. 
 */

public class JvmSwitchAnalyzer extends AbstractJavaAnalyzer {
	private static final String ANALYZER_NAME = "JVM Switch Analyzer";
	private static final String ANALYZER_DESCRIPTION =
		"Disassembles jump targets of tableswitch " + " and lookupswitch instructions";
	private static final String LOOKUPSWITCH_MNEMONIC = "lookupswitch";
	private static final String TABLESWITCH_MNEMONIC = "tableswitch";
	private static final String DEFAULT_CASE_LABEL = "default";

	@Override
	public String getName() {
		return ANALYZER_NAME;
	}

	@Override
	public AnalyzerType getAnalysisType() {
		return AnalyzerType.INSTRUCTION_ANALYZER;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public String getDescription() {
		return ANALYZER_DESCRIPTION;
	}

	@Override
	public AnalysisPriority getPriority() {
		return AnalysisPriority.DISASSEMBLY;
	}

	@Override
	public boolean canAnalyze(Program program) {
		try {
			return JavaClassUtil.isClassFile(program);
		}
		catch (Exception e) {
			// ignore
		}
		return false;
	}

	@Override
	public boolean isPrototype() {
		return false;
	}

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {
		monitor.setMaximum(set.getNumAddresses());
		monitor.setProgress(0);

		ByteProvider provider =
			new MemoryByteProvider(program.getMemory(), program.getMinAddress());
		BinaryReader reader = new BinaryReader(provider, false);

		Listing listing = program.getListing();
		InstructionIterator instructionIterator = listing.getInstructions(set, true);

		//find the switch instructions and process them
		while (instructionIterator.hasNext()) {
			Instruction instruction = instructionIterator.next();
			monitor.checkCanceled();
			monitor.incrementProgress(instruction.getLength());
			String mnenomic = instruction.getMnemonicString();
			if (!mnenomic.equals(TABLESWITCH_MNEMONIC) && !mnenomic.equals(LOOKUPSWITCH_MNEMONIC)) {
				continue; //only care about switch instructions
			}
			if (instruction.getMnemonicReferences().length > 0) {
				continue; //analyzer has already handled this instructions
			}
			monitor.setMessage("JvmSwitchAnalyzer: " + instruction.getMinAddress());
			if (instruction.getMnemonicString().equals(TABLESWITCH_MNEMONIC)) {
				processTableSwitch(program, reader, instruction, monitor);
			}
			else {
				processLookupSwitch(program, reader, instruction, monitor);
			}
		}
		return true;
	}

	private void processTableSwitch(Program program, BinaryReader bReader, Instruction instruction,
			TaskMonitor monitor) {
		Register alignmentPad = program.getRegister("alignmentPad");
		int alignment = instruction.getValue(alignmentPad, false).intValue();
		if (instruction.getOperandReferences(0).length == 0) {
			Msg.info(this,
				"Skipping tableswitch instruction at " + instruction.getAddress().toString() +
					" - missing operand reference for default case.");
			return;  //user manually deleted reference
		}

		// WARNING: this is very dependent on the sub-constructor for the switch stmt.
		//if the op-object order changes for the operand, this will fail
		Object[] opObjects = instruction.getOpObjects(0);
		Address defaultAddress = instruction.getOperandReferences(0)[0].getToAddress();
		long low = ((Scalar) opObjects[1]).getUnsignedValue();
		long high = ((Scalar) opObjects[2]).getUnsignedValue();

		List<Address> addressesToDisassemble = new ArrayList<>();

		//handle the default case
		addressesToDisassemble.add(defaultAddress);
		addLabelAndReference(program, instruction, defaultAddress, DEFAULT_CASE_LABEL);

		long base = instruction.getMemory().getMinAddress().getOffset();
		long index = instruction.getMinAddress().getOffset();
		index -= base;
		index += (1 + alignment + 4 + 4 + 4); //tableswitch opcode + alignment + size of default + size of low + size of high
		bReader.setPointerIndex(index);

		for (int i = 0; i <= high - low; i++) {
			try {
				int offset = bReader.readNextInt();
				Address toDis = instruction.getMinAddress().add(offset);
				addressesToDisassemble.add(toDis);
				String label = "case_" + (low + i) + "_(0x" + Long.toHexString(low + i) + ")";
				addLabelAndReference(program, instruction, toDis, label);
			}
			catch (IOException e) {
				Msg.error(this, e.getMessage());
			}
		}
		disassembleCases(program, addressesToDisassemble);
		fixupFunction(program, instruction, addressesToDisassemble, monitor);

	}

	private void processLookupSwitch(Program program, BinaryReader bReader, Instruction instruction,
			TaskMonitor monitor) {
		Register alignmentPad = program.getRegister("alignmentPad");
		int alignment = instruction.getValue(alignmentPad, false).intValue();

		// WARNING: this is very dependent on the sub-constructor for the switch stmt.
		//          if the op-object order changes for the operand, this will fail
		Object[] opObjects = instruction.getOpObjects(0);
		long defaultOffset = ((Scalar) opObjects[0]).getUnsignedValue();
		long numberOfCases = ((Scalar) opObjects[1]).getUnsignedValue();

		List<Address> addressesToDisassemble = new ArrayList<>();

		//handle the default case
		Address defaultAddress = instruction.getMinAddress().add(defaultOffset);
		addressesToDisassemble.add(defaultAddress);
		addLabelAndReference(program, instruction, defaultAddress, DEFAULT_CASE_LABEL);

		long base = instruction.getMemory().getMinAddress().getOffset();
		long index = instruction.getMinAddress().getOffset();
		index -= base;
		index += (1 + alignment + 4 + 4); //lookupswitch opcode + alignment + size of default + size of num pairs
		bReader.setPointerIndex(index);

		for (int i = 0; i < numberOfCases; i++) {
			try {
				int match = bReader.readNextInt();
				int offset = bReader.readNextInt();
				Address toDis = instruction.getMinAddress().add(offset);
				addressesToDisassemble.add(toDis);
				String label = "case_" + match + "_(0x" + Integer.toHexString(match) + ")";
				addLabelAndReference(program, instruction, toDis, label);
			}
			catch (IOException e) {
				Msg.error(this, e.getMessage());
			}
		}
		disassembleCases(program, addressesToDisassemble);
		fixupFunction(program, instruction, addressesToDisassemble, monitor);

	}

	private void disassembleCases(Program program, List<Address> addressesToDisassemble) {
		for (Address addr : addressesToDisassemble) {
			DisassembleCommand dCommand = new DisassembleCommand(addr, null, true);
			dCommand.applyTo(program);
		}
	}

	private void addLabelAndReference(Program program, Instruction switchInstruction,
			Address target, String label) {
		program.getReferenceManager().addMemoryReference(switchInstruction.getMinAddress(), target,
			RefType.COMPUTED_JUMP, SourceType.ANALYSIS, CodeUnit.MNEMONIC);

		//put switch table cases into namespace for the switch 
		//create namespace if necessary
		Namespace space = null;
		String switchName =
			switchInstruction.getMnemonicString() + "_" + switchInstruction.getAddress().toString();
		try {
			space = program.getSymbolTable().createNameSpace(null, switchName, SourceType.ANALYSIS);
		}
		catch (DuplicateNameException e) {
			space = program.getSymbolTable().getNamespace(switchName, null);
		}
		catch (InvalidInputException e) {
			// just go with default space
		}
		try {
			program.getSymbolTable().createLabel(target, label, space, SourceType.ANALYSIS);
		}
		catch (InvalidInputException e1) {
			Msg.error(this, e1.getMessage());
		}
	}

	private void fixupFunction(Program program, Instruction instruction, List<Address> additions,
			TaskMonitor monitor) {
		Function func =
			program.getFunctionManager().getFunctionContaining(instruction.getAddress());
		AddressSet newBody = new AddressSet(func.getBody());
		for (Address addr : additions) {
			newBody.add(addr);
		}
		try {
			func.setBody(newBody);
		}
		catch (OverlappingFunctionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			CreateFunctionCmd.fixupFunctionBody(program, func, monitor);
		}
		catch (CancelledException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
