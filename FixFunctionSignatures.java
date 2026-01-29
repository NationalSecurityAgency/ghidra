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
// Script to detect and fix MIPS function signatures with missing parameters
// @category Analysis.MIPS
// @author Augment Agent

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.*;

import java.util.*;

public class FixFunctionSignatures extends GhidraScript {

	@Override
	public void run() throws Exception {
		
		if (currentProgram == null) {
			println("No program loaded");
			return;
		}
		
		// Check if this is MIPS
		String processor = currentProgram.getLanguage().getProcessor().toString();
		if (!processor.toLowerCase().contains("mips")) {
			println("This script is for MIPS binaries only");
			return;
		}
		
		println("Analyzing MIPS function signatures...");
		println("");
		
		FunctionManager funcMgr = currentProgram.getFunctionManager();
		Listing listing = currentProgram.getListing();
		
		int functionsChecked = 0;
		int functionsFixed = 0;
		
		// MIPS argument registers: $a0, $a1, $a2, $a3
		Register a0 = currentProgram.getRegister("a0");
		Register a1 = currentProgram.getRegister("a1");
		Register a2 = currentProgram.getRegister("a2");
		Register a3 = currentProgram.getRegister("a3");
		
		for (Function func : funcMgr.getFunctions(true)) {
			if (monitor.isCancelled()) {
				break;
			}
			
			functionsChecked++;
			
			// Get current parameter count
			int currentParamCount = func.getParameterCount();
			
			// Analyze which argument registers are used
			int maxArgRegUsed = analyzeArgumentRegisters(func, listing, a0, a1, a2, a3);
			
			// If we detect more argument registers used than parameters declared
			if (maxArgRegUsed > currentParamCount) {
				println("Function: " + func.getName() + " @ " + func.getEntryPoint());
				println("  Current params: " + currentParamCount);
				println("  Detected args:  " + maxArgRegUsed + " (uses $a0-$a" + (maxArgRegUsed - 1) + ")");
				
				// Ask user if they want to fix it
				if (askYesNo("Fix Function Signature?", 
					"Function " + func.getName() + " appears to use " + maxArgRegUsed + 
					" arguments but only has " + currentParamCount + " parameters.\n\n" +
					"Add missing parameters?")) {
					
					fixFunctionSignature(func, maxArgRegUsed);
					functionsFixed++;
					println("  FIXED: Added " + (maxArgRegUsed - currentParamCount) + " parameters");
				}
				println("");
			}
		}
		
		println("");
		println("Summary:");
		println("  Functions checked: " + functionsChecked);
		println("  Functions fixed:   " + functionsFixed);
	}
	
	/**
	 * Analyze which MIPS argument registers are used in the function
	 * Returns the maximum argument register index used (1-4)
	 */
	private int analyzeArgumentRegisters(Function func, Listing listing, 
			Register a0, Register a1, Register a2, Register a3) {
		
		int maxArgReg = 0;
		
		// Check first 20 instructions for argument register usage
		InstructionIterator iter = listing.getInstructions(func.getBody(), true);
		int count = 0;
		
		while (iter.hasNext() && count < 20) {
			Instruction instr = iter.next();
			count++;
			
			// Check all operands
			for (int i = 0; i < instr.getNumOperands(); i++) {
				Object[] objs = instr.getOpObjects(i);
				for (Object obj : objs) {
					if (obj instanceof Register) {
						Register reg = (Register) obj;
						
						// Check which argument register this is
						if (reg.equals(a0)) {
							maxArgReg = Math.max(maxArgReg, 1);
						} else if (reg.equals(a1)) {
							maxArgReg = Math.max(maxArgReg, 2);
						} else if (reg.equals(a2)) {
							maxArgReg = Math.max(maxArgReg, 3);
						} else if (reg.equals(a3)) {
							maxArgReg = Math.max(maxArgReg, 4);
						}
					}
				}
			}
		}
		
		return maxArgReg;
	}
	
	/**
	 * Fix function signature by adding missing parameters
	 */
	private void fixFunctionSignature(Function func, int paramCount) throws Exception {
		
		// Create parameter list
		List<ParameterImpl> params = new ArrayList<>();
		
		// Keep existing parameters
		for (Parameter param : func.getParameters()) {
			params.add(new ParameterImpl(param.getName(), param.getDataType(), 
				currentProgram, param.getSource()));
		}
		
		// Add missing parameters
		int currentCount = params.size();
		for (int i = currentCount; i < paramCount; i++) {
			String paramName = "arg" + (i + 1);
			DataType paramType = new PointerDataType(); // Default to void*
			params.add(new ParameterImpl(paramName, paramType, currentProgram));
		}
		
		// Update function signature
		func.updateFunction(null, null, params, 
			FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.ANALYSIS);
	}
}

