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
	
	private static final String SWITCH_OPTION_NAME = "Switch Table Recovery";
	private static final String SWITCH_OPTION_DESCRIPTION = "Turn on to recover switch tables (not implemented yet !)";
	private static final boolean SWITCH_OPTION_DEFAULT_VALUE = false;
	
	private static final String RECOVER_GP_OPTION_NAME = "Recover global GP register writes";
	private static final String RECOVER_GP_OPTION_DESCRIPTION = "Reads the global GP value from the symbol _SDA_BASE_";
	private static final boolean RECOVER_GP_OPTION_DEFAULT_VALUE = true;
	
	
	private boolean recoverSwitchTables = SWITCH_OPTION_DEFAULT_VALUE;
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

		options.registerOption(SWITCH_OPTION_NAME, recoverSwitchTables, null,
				SWITCH_OPTION_DESCRIPTION);
		recoverSwitchTables = options.getBoolean(SWITCH_OPTION_NAME, recoverSwitchTables);

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
	 * @param set
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

		ContextEvaluator eval = new ConstantPropagationContextEvaluator(trustWriteMemOption) {
			@Override
			public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
				FlowType flowtype = instruction.getFlowType();
				if (!flowtype.isJump()) {
					return false;
				}

				if (recoverSwitchTables) {
					String mnemonic = instruction.getMnemonicString();
					if (mnemonic.equals("jr")) {
						fixJumpTable(program, instruction, monitor);
					}
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
	
	/**
	 * @param program
	 * @param startInstr
	 * @param monitor
	 */
	private void fixJumpTable(Program program, Instruction startInstr, TaskMonitor monitor) {
		/* TODO: implement switch recovery ?
		 * We are looking for tables like this :
		 * 
		 * slti45  a0,0x4						<- table size
		 * beqzs8  LAB_005159ea					<- default jump
		 * sethi   ta, 0x515
		 * ori     ta, ta, 0x9a0
		 * lw      a0, [ta + (a0 << 0x2)]		<- ref to table
		 * jr      a0							<- table jump
		 */
	}
}
