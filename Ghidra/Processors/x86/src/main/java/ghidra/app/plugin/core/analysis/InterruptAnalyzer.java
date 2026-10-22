package ghidra.app.plugin.core.analysis;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * x86 Interrupt analyzer interface.
 */
public interface InterruptAnalyzer {
	
	/**
	 * Interrupt handler callback.
	 * 
	 * @param function the function the given instruction belongs to.
	 * @param instruction the instruction to analyze.
	 * @param monitor the task monitor to detect cancellation requests.
	 * @return true whether analysis should continue to the following
	 * instruction, false otherwise.
	 * @throws CancelledException if analysis has been cancelled by the user
	 * in the meantime.
	 */
	boolean processInstruction(Function function, Instruction instruction, TaskMonitor monitor) throws CancelledException;
}
