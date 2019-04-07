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

import java.math.BigInteger;

import ghidra.app.services.*;
import ghidra.app.util.bin.format.pef.PefConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PefLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class PefAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "PEF Indirect Addressing";
	private static final String DESCRIPTION =
		"Creates references to symbols indirectly addresses via R2.";

	public PefAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.DATA_ANALYSIS.before().before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		return PefLoader.PEF_NAME.equals(program.getExecutableFormat());
	}

	/**
	 * Creates a reference on any operand that uses
	 * reads an offset from r2.
	 */
	@Override
	public boolean added(Program program, AddressSetView functionSet, TaskMonitor monitor,
			MessageLog log) {
		SymbolTable symbolTable = program.getSymbolTable();
		Listing listing = program.getListing();
		ReferenceManager referenceManager = program.getReferenceManager();
		Symbol tocSymbol = SymbolUtilities.getExpectedLabelOrFunctionSymbol(program,
			PefConstants.TOC, err -> log.error(getName(), err));
		if (tocSymbol == null) {
			return true;
		}
		AddressSet instructionSet =
			getInstructionSet(program, functionSet, listing, tocSymbol, monitor);
		InstructionIterator instructions = listing.getInstructions(instructionSet, true);
		while (instructions.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			Instruction instruction = instructions.next();
			if (instruction.getNumOperands() != 2) {
				continue;
			}
			Object[] operandObjects1 = instruction.getOpObjects(1);//op objects from 1st operand
			if (operandObjects1.length != 2) {
				continue;
			}
			if (!(operandObjects1[0] instanceof Scalar)) {
				continue;
			}
			if (!(operandObjects1[1] instanceof Register)) {
				continue;
			}
			Register register = (Register) operandObjects1[1];
			if (!register.getName().equals("r2")) {
				continue;
			}
			Scalar scalar = (Scalar) operandObjects1[0];
			Address destAddr = createReference(referenceManager, tocSymbol, instruction, scalar);
			markupGlueCode(listing, symbolTable, instruction, destAddr);
		}
		return true;
	}

	/**
	 * Creates a address set consisting of the function bodies of each
	 * function entry point specified in the function address set.
	 */
	private AddressSet getInstructionSet(Program program, AddressSetView functionSet,
			Listing listing, Symbol tocSymbol, TaskMonitor monitor) {
		AddressSet instructionSet = new AddressSet();
		FunctionIterator functions = listing.getFunctions(functionSet, true);
		Register r2 = program.getRegister("r2");
		BigInteger val = BigInteger.valueOf(tocSymbol.getAddress().getOffset());
		RegisterValue regVal = new RegisterValue(r2, val);
		while (functions.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			Function function = functions.next();
			try {
				program.getProgramContext().setRegisterValue(function.getEntryPoint(),
					function.getEntryPoint(), regVal);
			}
			catch (ContextChangeException e) {
				// should never happen when changing r2 register
			}
			instructionSet.add(function.getBody());
		}
		return instructionSet;
	}

	/**
	 * Checks for glue code and propagates the function name up.
	 * <p>
	 * If the instruction is in the form of:
	 * <p>
	 * <code>lwz r12,0x20(r2)</code>
	 * <p>
	 * Then it renames the function containing the instruction
	 * with the symbol's name defined at the address computed
	 * using 0x20(r2).
	 */
	private void markupGlueCode(Listing listing, SymbolTable symbolTable, Instruction instruction,
			Address symbolAddress) {

		Object[] operandObjects0 = instruction.getOpObjects(0);//op objects from 0th operand
		if (operandObjects0.length != 1) {
			return;
		}
		if (!(operandObjects0[0] instanceof Register)) {
			return;
		}
		Register register = (Register) operandObjects0[0];
		if (!register.getName().equals("r12")) {
			return;
		}
		if (!instruction.getMnemonicString().equals("lwz")) {
			return;
		}
		Function function = listing.getFunctionContaining(instruction.getMinAddress());
		if (function == null) {
			return;
		}
		if (function.getSymbol().getSource() == SourceType.IMPORTED ||
			function.getSymbol().getSource() == SourceType.USER_DEFINED) {
			return;
		}
		Symbol symbol = symbolTable.getPrimarySymbol(symbolAddress);
		if (symbol == null || symbol.isDynamic()) {
			return;
		}
		try {
			Namespace glueNamespace = getNamespace(symbolTable, PefConstants.GLUE);
			function.getSymbol().setNamespace(glueNamespace);
			function.getSymbol().setName(symbol.getName(), SourceType.ANALYSIS);
		}
		catch (Exception e) {//don't care
		}
	}

	private Address createReference(ReferenceManager referenceManager, Symbol tocSymbol,
			Instruction instruction, Scalar scalar) {
		Address destinationAddress = tocSymbol.getAddress().add(scalar.getSignedValue());
		Reference reference = referenceManager.addMemoryReference(instruction.getMinAddress(),
			destinationAddress, RefType.READ, SourceType.ANALYSIS, 1);
		referenceManager.setPrimary(reference, false);
		return destinationAddress;
	}

	private Namespace getNamespace(SymbolTable symbolTable, String namespaceName) throws Exception {
		Namespace namespace = symbolTable.getNamespace(namespaceName, null);
		if (namespace == null) {
			namespace = symbolTable.createNameSpace(null, namespaceName, SourceType.IMPORTED);
		}
		return namespace;
	}

}
