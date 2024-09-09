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

import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.services.AnalysisPriority;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyze Sparc binaries for certain patterns of instructions.
 *
 */

public class SparcAnalyzer extends ConstantPropagationAnalyzer {

	private final static String PROCESSOR_NAME = "Sparc";
	

	// option to turn off o7 call return  analysis
	protected static final String O7_CALLRETURN_NAME = "Call/Return o7 check";
	protected static final String O7_CALLRETURN_DESCRIPTION =
		"Turn on check for setting of o7 return link register in delay slot of all calls";
	protected static final boolean EO7_CALLRETURN_DEFAULT_VALUE = true;
	protected boolean o7CallReturnAnalysis = EO7_CALLRETURN_DEFAULT_VALUE;

	public SparcAnalyzer() {
		super(PROCESSOR_NAME);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor processor = program.getLanguage().getProcessor();
		
		return processor.equals(Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public AddressSetView flowConstants(final Program program, Address flowStart, AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {

		Register linkReg = program.getRegister("o7");

		// follow all flows building up context
		// use context to fill out addresses on certain instructions 
		ConstantPropagationContextEvaluator eval = new ConstantPropagationContextEvaluator(monitor, trustWriteMemOption) {

			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				FlowType ftype = instr.getFlowType();
				// Check for a call with a restore in the delay slot
				//    Then it is a non-returning call (share the called function return
				if (o7CallReturnAnalysis && ftype.isCall()) {
					Address fallAddr = instr.getFallThrough();
					if (fallAddr == null) {
						return false;
					}
					Instruction delayInstr =
						instr.getProgram().getListing().getInstructionAfter(instr.getMaxAddress());
					if (delayInstr == null) {
						return false;
					}
					PcodeOp[] pcode = delayInstr.getPcode();
					for (PcodeOp pcodeOp : pcode) {
						Varnode output = pcodeOp.getOutput();
						if (output == null || !output.equals(context.getRegisterVarnode(linkReg))) {
							continue;
						}
						Varnode input = pcodeOp.getInput(0);
						if (input.isConstant()) {
							continue; // this is just assigning the return value after the call
						}
						instr.setFallThrough(null);
						Instruction fallInstr =
							instr.getProgram().getListing().getInstructionAt(fallAddr);
						if (fallInstr == null) {
							return false;
						}
						if (fallInstr.getReferenceIteratorTo().hasNext()) {
							return false;
						}
						ClearFlowAndRepairCmd cmd =
							new ClearFlowAndRepairCmd(fallAddr, false, false, true);
						cmd.applyTo(instr.getProgram(), monitor);
						
						break;
					}
				}
				return false;
			}

			@Override
			public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
				FlowType flowType = instruction.getFlowType();
				if (!flowType.isJump()) {
					return false;
				}
				// TODO: if this is a switch stmt, add to destSet
				Reference[] refs = instruction.getReferencesFrom();
				if (refs.length <= 0 ||
					(refs.length == 1 && refs[0].getReferenceType().isData())) {
					destSet.addRange(instruction.getMinAddress(), instruction.getMinAddress());
				}
				return false;
			}
		};
		
		eval.setTrustWritableMemory(trustWriteMemOption)
		    .setMinSpeculativeOffset(minSpeculativeRefAddress)
		    .setMaxSpeculativeOffset(maxSpeculativeRefAddress)
		    .setMinStoreLoadOffset(minStoreLoadRefAddress)
		    .setCreateComplexDataFromPointers(createComplexDataFromPointers);
		
		AddressSet resultSet = symEval.flowConstants(flowStart, flowSet, eval, true, monitor);

		return resultSet;
	}
	
	
	@Override
	public void registerOptions(Options options, Program program) {
		super.registerOptions(options, program);
		options.registerOption(O7_CALLRETURN_NAME, o7CallReturnAnalysis, null, O7_CALLRETURN_DESCRIPTION);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
		o7CallReturnAnalysis = options.getBoolean(O7_CALLRETURN_NAME, o7CallReturnAnalysis);
	}
}
