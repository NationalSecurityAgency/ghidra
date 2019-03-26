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

import ghidra.app.services.AnalysisPriority;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Pic16Analyzer extends ConstantPropagationAnalyzer {
	private static final String PROCESSOR_NAME = "PIC-16";

	private static final int INSTRUCTION_LENGTH = 2;

	private static final String CODE_SPACE_NAME = "CODE";

	public Pic16Analyzer() {
		super(PROCESSOR_NAME);
		setPriority(AnalysisPriority.DISASSEMBLY.after().after().after());
	}

	private Register statusReg;
	private Register pclathReg;
	private Register pclReg;
	private Register wReg;
	private Register bsrReg;

	private Register rpStatusReg;
	private Register irpStatusReg;
	
	private AddressSet disassemblyPoints;
	
	@Override
	public boolean canAnalyze(Program p) {
		Language lang = p.getLanguage();
		statusReg = p.getRegister("STATUS");
		pclathReg = p.getRegister("PCLATH");
		pclReg = p.getRegister("PCL");
		wReg = p.getRegister("W");
		bsrReg = p.getRegister("BSR");
		
		rpStatusReg = p.getRegister("RP");
		irpStatusReg = p.getRegister("IRP");
		
		return lang.getProcessor() == PicProcessor.PROCESSOR_PIC_16 && pclathReg != null;
	}

	@Override
	public synchronized boolean added(Program p, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		disassemblyPoints = new AddressSet();
		
		return super.added(p, set, monitor, log);
	}
	
	@Override
	public AddressSet flowConstants(final Program program, Address flowStart, AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {
		
		// follow all flows building up context
		// use context to fill out addresses on certain instructions 
		ContextEvaluator eval = new ConstantPropagationContextEvaluator(trustWriteMemOption) {
			
			@Override
			public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop, Address address,
					int size, RefType refType) {
				AddressSpace space = address.getAddressSpace();

				if (space.hasMappedRegisters()) {
					return true;
				}
				boolean isCodeSpace = address.getAddressSpace().getName().equals(CODE_SPACE_NAME);
				if (refType.isComputed() && refType.isFlow() && isCodeSpace) {
					return true;
				}
				return super.evaluateReference(context, instr, pcodeop, address, size, refType);
			}
			
			@Override
			public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
				FlowType flowType = instruction.getFlowType();
				if (!flowType.isFlow()) {
					return false;
				}
				
				Reference[] refs = instruction.getReferencesFrom();
				if (refs.length == 1 && refs[0].getReferenceType().isFlow()) {
					writeContext(refs[0].getToAddress(), context);
					Address dest = refs[0].getToAddress();
					disassemblyPoints.addRange(dest, dest);
				}
				
				return false;
			}

			private void writeContext(Address dest, VarnodeContext context) {
				flowRegister(dest, context, bsrReg);
				flowRegister(dest, context, statusReg);
				flowRegister(dest, context, pclathReg);
				flowRegister(dest, context, pclReg);
				flowRegister(dest, context, wReg);
				
				flowRegister(dest, context, rpStatusReg);
				flowRegister(dest, context, irpStatusReg);
				startNewBlock(program, dest);
			}

			private void flowRegister(Address dest, VarnodeContext context, Register reg) {
				ProgramContext programContext = program.getProgramContext();
				if (reg == null) {
					return;
				}
				RegisterValue rValue = context.getRegisterValue(reg);
				if (rValue == null) {
					return;
				}
				try {
					programContext.setRegisterValue(dest, dest, rValue);
				} catch (ContextChangeException e) {
					e.printStackTrace();
				}
			}
		};
		
		startNewBlock(program, flowStart);
		
		AddressSet result = symEval.flowConstants(flowStart, flowSet, eval, true, monitor);

		if (!disassemblyPoints.isEmpty()) {
			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
			mgr.disassemble(disassemblyPoints);
		}
		
		return result;
	}
	
	private void startNewBlock(Program program, Address flowStart) {
		long instrOffset = flowStart.getOffset();
		
		RegisterValue pclathValue = program.getProgramContext().getRegisterValue(pclathReg, flowStart);
		if (pclathValue != null) {
			return;
		}
		
		long pclValue = (instrOffset / INSTRUCTION_LENGTH) >> 8;
		
		pclathValue = new RegisterValue(pclathReg, BigInteger.valueOf(pclValue));
		try {
			program.getProgramContext().setRegisterValue(flowStart, flowStart, pclathValue);
		} catch (ContextChangeException e) {
			e.printStackTrace();
		}
	}
}		
