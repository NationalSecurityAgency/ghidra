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

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class NDS32Analyzer extends ConstantPropagationAnalyzer {
	private final static String PROCESSOR_NAME = "NDS32";
	
	private static final String RECOVER_GP_OPTION_NAME = "Recover global GP register writes";
	private static final String RECOVER_GP_OPTION_DESCRIPTION = "Reads the global GP value from the symbol _SDA_BASE_";
	private static final boolean RECOVER_GP_OPTION_DEFAULT_VALUE = true;
	
	
	//private boolean recoverSwitchTables = SWITCH_OPTION_DEFAULT_VALUE;
	private boolean recoverGp = RECOVER_GP_OPTION_DEFAULT_VALUE;

	private Address gpAssumptionValue = null;

	private Register gp;

	public NDS32Analyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		boolean canAnalyze = program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));

		if (!canAnalyze) {
			return false;
		}

		gp = program.getRegister("gp");
		
		return true;
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);

		options.registerOption(RECOVER_GP_OPTION_NAME, recoverGp, null,
				RECOVER_GP_OPTION_DESCRIPTION);
		recoverGp = options.getBoolean(RECOVER_GP_OPTION_NAME, recoverGp);
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		gpAssumptionValue = null;

		checkForGlobalGP(program, set, monitor);

		return super.added(program, set, monitor, log);
	}

	/**
	 * Check for a global GP register symbol or discovered symbol
	 * @param program
	 * @param set
	 * @param monitor
	 */
	private void checkForGlobalGP(Program program, AddressSetView set, TaskMonitor monitor) {
		if (!recoverGp) {
			return;
		}

		Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(program, "_SDA_BASE_",
			err -> Msg.error(this, err));
		if (symbol != null) {
			gpAssumptionValue = symbol.getAddress();
			return;
		}

		// TODO : if the symbol doesn't exist, check manually... somewhere else
		
		return;
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {
		
		// get the function body
		final Function func = program.getFunctionManager().getFunctionContaining(flowStart);

		final AddressSet coveredSet = new AddressSet();
		
		Address currentGPAssumptionValue = gpAssumptionValue;

		// TODO : copypaste more code from MipsAddressAnalyzer to see if gp is written and act accordingly
		if (func != null) {
			flowStart = func.getEntryPoint();
			if (currentGPAssumptionValue != null) {
				ProgramContext programContext = program.getProgramContext();
				RegisterValue gpVal = programContext.getRegisterValue(gp, flowStart);
				if (gpVal == null || !gpVal.hasValue()) {
					gpVal = new RegisterValue(gp,
						BigInteger.valueOf(currentGPAssumptionValue.getOffset()));
					try {
						program.getProgramContext().setRegisterValue(func.getEntryPoint(),
							func.getEntryPoint(), gpVal);
					}
					catch (ContextChangeException e) {
						throw new AssertException("unexpected", e); // only happens for context register
					}
				}
			}
		}

		ContextEvaluator eval = new ConstantPropagationContextEvaluator(monitor, trustWriteMemOption) {
			@Override
			public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
				FlowType flowtype = instruction.getFlowType();
				if (!flowtype.isJump()) {
					return false;
				}

				return false;
			}
		};
		
		AddressSet resultSet = symEval.flowConstants(flowStart, null, eval, true, monitor);

		// Add in any addresses we should assume got covered
		//   These addresses are put on because we had to stop analysis due to an unknown register value
		resultSet.add(coveredSet);

		return resultSet;
	}
	
}
