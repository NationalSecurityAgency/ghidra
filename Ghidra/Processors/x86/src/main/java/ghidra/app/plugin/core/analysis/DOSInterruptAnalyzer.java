package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DOSInterruptAnalyzer extends AbstractAnalyzer {
	
	private static final String NAME = "Resolve DOS interrupts";
	private static final String DESCRIPTION = "Resolves selected DOS interrupt calls.";
	private static final String LANGUAGE = "x86:LE:16:Real Mode";
	
	/** Registered interrupt analyzers container. */
	private Map<Integer, InterruptAnalyzer> interruptAnalyzers = new HashMap<>();

	public DOSInterruptAnalyzer() {
		this(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
	}
	
	public DOSInterruptAnalyzer(String name, String description, AnalyzerType type) {
		super(name, description, type);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		
		addInterruptAnalyzer(0x20, new Int20hAnalyzer());
		addInterruptAnalyzer(0x21, new Int21hAnalyzer());
	}
	
	/**
	 * Attaches the given interrupt analyzer to a specific interrupt number.
	 * 
	 * At the moment there is no provision for interrupt analyzers chaining.
	 * 
	 * @param number the number of the interrupt to attach to.
	 * @param analyzer the analyzer to attach.
	 * @return true if the analyzer was successfully attached, false otherwise.
	 */
	public boolean addInterruptAnalyzer(int number, InterruptAnalyzer analyzer) {
		if (number < 0 || number > 255 || analyzer == null || interruptAnalyzers.containsKey(number)) {
			return false;
		}
		
		interruptAnalyzers.put(number, analyzer);
		return true;
	}

	/**
	 * Detaches analyzers from a specific interrupt number.
	 * 
	 * At the moment there is no provision for interrupt analyzer chaining.
	 * 
	 * @param number the number of the interrupt to detach analyzers from.
	 * @return true if the analyzer was successfully detached, false otherwise.
	 */
	public void removeInterruptAnalyzer(int number) {
		if (number < 0 || number > 255 || !interruptAnalyzers.containsKey(number)) {
			return;
		}
		
		interruptAnalyzers.remove(number);
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {		
		for (Function function : program.getFunctionManager().getFunctions(true)) {
			AddressSetView addressSetView = function.getBody();
			InstructionIterator instructionIterator = program.getListing().getInstructions(addressSetView, true);
			
			boolean shouldContinue = true;
			while (instructionIterator.hasNext() && shouldContinue) {
				shouldContinue = analyzeInstruction(function, instructionIterator.next(), monitor);
			}
		}
		
		return true;
	}
	
	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getLanguageID().getIdAsString().equals(LANGUAGE);
	}
	
	/**
	 * Analyzes a single instruction and if it is an interrupt call invokes a
	 * secondary analyzer for more in-depth processing.
	 * 
	 * @param function the function the given instruction belongs to.
	 * @param instruction the instruction to analyze.
	 * @param monitor the task monitor to detect cancellation requests.
	 * @return true whether analysis should continue to the following
	 * instruction, false otherwise. 
	 * @throws CancelledException if analysis has been cancelled by the user
	 * in the meantime.
	 */
	private boolean analyzeInstruction(Function function, Instruction instruction, TaskMonitor monitor)
			throws CancelledException {
		
		if (!instruction.getMnemonicString().equals("INT") || instruction.getNumOperands() <= 0) {
			return true;
		}
		
		int interruptNumber = (int) ((Scalar) instruction.getScalar(0)).getValue();
		InterruptAnalyzer analyzer = interruptAnalyzers.getOrDefault(interruptNumber, null);
		if (analyzer != null) {
			return analyzer.processInstruction(function, instruction, monitor);
		}
		
		return true;
	}

	/**
	 * Utility class to track assignments to a particular register from a propagator.
	 */
	static class AssignmentContextEvaluator extends ContextEvaluatorAdapter {

		/** The register to track assignments to. */
		private Register targetRegister;
		
		/** The last address to track assignments in. */
		private Address endAddress;
		
		/** The last seen register value. */
		private RegisterValue registerValue;
		
		/**
		 * Creates the evaluator instance.
		 * 
		 * @param target the register to track assignments to.
		 * @param end the last address to track assignments in.
		 */
		public AssignmentContextEvaluator(Register target, Address end) {
			targetRegister = target;
			endAddress = end;
		}
		
		@Override
		public boolean evaluateContext(VarnodeContext context, Instruction instr) {
			RegisterValue value = context.getRegisterValue(targetRegister);
			if (value != null) {
				registerValue = value;
			}
			
			return instr.getAddress().equals(endAddress);
		}
		
		/**
		 * Returns the last seen register value.
		 * 
		 * @return the last seen register value.
		 */
		public RegisterValue getRegisterValue() {
			return registerValue;
		}
	}
	
	/**
	 * DOS INT 20h analyzer.
	 * 
	 * All calls to INT 20h, regardless of the registers state should imply
	 * the immediate program termination.
	 * 
	 * If an INT 20h instruction is found, the current function is resized
	 * to have its end address as the address where the opcode was seen.
	 */
	static private class Int20hAnalyzer implements InterruptAnalyzer {

		@Override
		public boolean processInstruction(Function function, Instruction instruction, TaskMonitor monitor)
				throws CancelledException {

			// Resize the current function.
			
			Address instructionAddress = instruction.getAddress();
			if (!function.getBody().getMaxAddress().equals(instructionAddress)) {
				try {
					function.setBody(new AddressSet(function.getEntryPoint(), instructionAddress));
				} catch (AddressOutOfBoundsException | OverlappingFunctionException e) {
					e.printStackTrace();
				}
			}
			
			// No further function analysis is needed.

			return false;
		}	
	}
	
	/**
	 * DOS INT 21h analyzer.
	 * 
	 * INT 21h is the entry point for most if not all DOS functions, therefore
	 * analysis is a bit more complex.  At this time only function 0x4C is
	 * handled, which signals the program termination.
	 * 
	 * If an INT 21h instruction with AH being 0x4C is found, the current
	 * function is resized to have its end address as the address where the
	 * opcode was seen.
	 */
	static private class Int21hAnalyzer implements InterruptAnalyzer {

		@Override
		public boolean processInstruction(Function function, Instruction instruction, TaskMonitor monitor)
				throws CancelledException {

			Address instructionAddress = instruction.getAddress();
			
			if (function.getBody().getMaxAddress().equals(instructionAddress)) {

				// End of function reached.
				
				return false;
			}
				
			// Get the value of AH at this point in the function.
				
			AssignmentContextEvaluator contextEvaluator = new AssignmentContextEvaluator(
					instruction.getRegister("AH"), function.getBody().getMaxAddress());
			SymbolicPropogator propagator = new SymbolicPropogator(function.getProgram());
			propagator.flowConstants(function.getEntryPoint(), null, contextEvaluator, true, monitor);
				
			// If AH was detected being 0x4C, resize the current function.
				
			RegisterValue callCode = contextEvaluator.getRegisterValue();
			if (callCode != null) {
				BigInteger value = callCode.getUnsignedValue();
				if (value != null && value.intValue() == 0x4C) {
					try {
						function.setBody(new AddressSet(function.getEntryPoint(), instructionAddress));
					} catch (AddressOutOfBoundsException | OverlappingFunctionException e) {
						e.printStackTrace();
					}
						
					// No further function analysis is needed.
						
					return false;
				}
			}
			
			return true;
		}	
	}	
}
