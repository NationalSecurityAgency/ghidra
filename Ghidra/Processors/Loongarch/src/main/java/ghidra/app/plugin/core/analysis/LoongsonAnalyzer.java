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

import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class LoongsonAnalyzer extends ConstantPropagationAnalyzer {
	
	private Register linkRegister;

	private final static String PROCESSOR_NAME = "Loongarch";

	public LoongsonAnalyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		boolean canAnalyze = program.getLanguage()
				.getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));

		if (!canAnalyze) {
			return false;
		}
		
		linkRegister = program.getProgramContext().getRegister("ra");

		return true;
	}

	@Override
	public AddressSet flowConstants(final Program program, final Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {

		// follow all flows building up context
		// use context to fill out addresses on certain instructions
		ConstantPropagationContextEvaluator eval =
			new ConstantPropagationContextEvaluator(monitor, trustWriteMemOption) {

				/**
				 * Check if there are any data references to this location.
				 * @param program
				 * @param addr
				 * @return true if there are any data references to addr
				 */
				private boolean hasDataReferenceTo(Program program, Address addr) {
					ReferenceManager refMgr = program.getReferenceManager();
					if (!refMgr.hasReferencesTo(addr)) {
						return false;
					}
					ReferenceIterator referencesTo = refMgr.getReferencesTo(addr);
					while (referencesTo.hasNext()) {
						Reference reference = referencesTo.next();
						if (reference.getReferenceType().isData()) {
							return true;
						}
					}
					return false;
				}

				private boolean isLinkRegister(VarnodeContext context, Varnode pcVal) {
					return (pcVal.isRegister() &&
						pcVal.getAddress().equals(linkRegister.getAddress())) ||
						(context.isSymbol(pcVal) && pcVal.getAddress()
								.getAddressSpace()
								.getName()
								.equals(linkRegister.getName()) &&
							pcVal.getOffset() == 0);
				}

				@Override
				public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
					return super.evaluateDestination(context, instruction);
				}

				@Override
				public boolean evaluateReturn(Varnode retVN, VarnodeContext context,
						Instruction instruction) {
					// check if a return is actually returning, or is branching with a constant PC

					// if flow already overridden, don't override again
					if (instruction.getFlowOverride() != FlowOverride.NONE) {
						return false;
					}

					if (retVN != null && context.isConstant(retVN)) {
						long offset = retVN.getOffset();
						if (offset > 3 && offset != -1) {
							FlowOverride flowOverride = FlowOverride.CALL_RETURN;
							// need to override the return flow to a branch
							instruction.setFlowOverride(flowOverride);
							
							// need to analyze this flow again with the new return tag
							AutoAnalysisManager aMgr= AutoAnalysisManager.getAnalysisManager(program);
							aMgr.codeDefined(flowStart);
						}
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
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
	}

}
