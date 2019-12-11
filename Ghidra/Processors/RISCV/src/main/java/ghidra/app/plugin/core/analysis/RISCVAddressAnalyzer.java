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

import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;

import java.math.BigInteger;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

public class RISCVAddressAnalyzer extends ConstantPropagationAnalyzer {

    public static final String RISCV___GLOBAL_POINTER = "__global_pointer$";
    
    private Address gp_assumption_value;
    
    private static final String REGISTER_GP = "gp";
    private Register gp;
    
    private static final String PROCESSOR_NAME = "RISCV";

    public RISCVAddressAnalyzer() {
		super(PROCESSOR_NAME);
	}
    
    @Override
	public boolean canAnalyze(Program program) {
		boolean canAnalyze = program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));

		if (!canAnalyze) {
			return false;
		}
		
		gp = program.getRegister(REGISTER_GP);
		
		return true;
    }
    
    @Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		gp_assumption_value = null;

		// check for the __global_pointer$ symbol to see what the global gp
		// value should be
		checkForGlobalGP(program, set, monitor);

		return super.added(program, set, monitor, log);
	}
    
    @Override
	public AddressSetView flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {
    	
    	// get the function body
		final Function func = program.getFunctionManager().getFunctionContaining(flowStart);

		final AddressSet coveredSet = new AddressSet();

		if (func != null && gp_assumption_value != null) {
			ProgramContext programContext = program.getProgramContext();
			RegisterValue gpVal = programContext.getRegisterValue(gp, flowStart);
			if (gpVal == null || !gpVal.hasValue()) {
				gpVal = new RegisterValue(gp, BigInteger.valueOf(gp_assumption_value.getOffset()));
				try {
					program.getProgramContext().setRegisterValue(func.getEntryPoint(),
						func.getEntryPoint(), gpVal);
				}
				catch (ContextChangeException e) {
					// only happens for context register
					throw new AssertException("unexpected", e);
				}
			}
		}
		
		// follow all flows building up context
		ConstantPropagationContextEvaluator eval =
				new ConstantPropagationContextEvaluator(trustWriteMemOption) {
			private boolean mustStopNow = false;
			
			@Override
			public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
				return mustStopNow;
			}
			
			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				return mustStopNow;
			}
		};
		AddressSet resultSet = symEval.flowConstants(flowStart, null, eval, true, monitor);
		resultSet.add(coveredSet);

		return resultSet;
    }
    
	/**
	 * Check for a global GP register symbol or discovered symbol
	 * @param program
	 * @param set
	 * @param monitor
	 */
	private void checkForGlobalGP(Program program, AddressSetView set, TaskMonitor monitor) {
		Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(program,
				RISCV___GLOBAL_POINTER,
				err -> Msg.error(this, err));
		if (symbol != null) {
			gp_assumption_value = symbol.getAddress();
			return;
		}
	}
}
