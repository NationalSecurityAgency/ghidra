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

import ghidra.app.services.AnalysisPriority;
import ghidra.app.util.viewer.field.HexagonParallelInstructionHelper;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class HexagonAnalyzer extends ConstantPropagationAnalyzer {
	private final static String PROCESSOR_NAME = "Hexagon";

	private Register r25Register;
	private Register lrRegister;
	private Register lrNewRegister;

	HexagonParallelInstructionHelper helper = new HexagonParallelInstructionHelper();

	protected int pass;

	public HexagonAnalyzer() {
		super(PROCESSOR_NAME);
		setPriority(AnalysisPriority.CODE_ANALYSIS.after());
	}

	@Override
	public boolean canAnalyze(Program program) {
		Language language = program.getLanguage();
		r25Register = program.getRegister("R25");
		lrRegister = program.getRegister("LR");
		lrNewRegister = program.getRegister("LR.new");
		if (language.getProcessor().equals(Processor.findOrPossiblyCreateProcessor("Hexagon")) &&
			r25Register != null && lrRegister != null && lrNewRegister != null) {
			return true;
		}
		return false;
	}

	@Override

	public AddressSetView flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {

		// follow all flows building up context
		// use context to fill out addresses on certain instructions 
		ConstantPropagationContextEvaluator eval =
			new ConstantPropagationContextEvaluator(monitor, trustWriteMemOption) {
				@Override
				public boolean evaluateContext(VarnodeContext context, Instruction instr) {
//				if (instr.getMnemonicString().equals("assign")) {
//					Register destReg = instr.getRegister(0);
//					if (destReg.getBitLength() == 16) {
//						String regName = destReg.getName();
//						Register shadowDest =
//							program.getRegister(regName.substring(0, regName.length() - 1));
//						Scalar s = instr.getScalar(1);
//						if (s != null) {
//							context.setValue(shadowDest, s.getBigInteger());
//						}
//						context.propogateResults(true);
//						BigInteger rval = context.getValue(program.getRegister("R0"), false);
//						Msg.info(this, rval == null ? "NULL" : rval.toString(16));
//						rval = context.getValue(program.getRegister("R0.L"), false);
//						Msg.info(this, rval == null ? "NULL" : rval.toString(16));
//						rval = context.getValue(program.getRegister("R0.H"), false);
//						Msg.info(this, rval == null ? "NULL" : rval.toString(16));
//					}
//				}

					FlowType ftype = instr.getFlowType();
					if (ftype.isComputed() && ftype.isJump()) {
						// TODO: MUST get the value... of the PC????
						Varnode destVal = null; // context.getRegisterVarnodeValue(indirectFlowDestReg);
						if (destVal != null) {
							if (isLinkRegister(context, destVal)) {
								// need to set the return override
								instr.setFlowOverride(FlowOverride.RETURN);
							}
						}
					}
					return false;
				}

				private boolean isLinkRegister(VarnodeContext context, Varnode destVal) {
					Address destAddr = destVal.getAddress();
					if (destVal.isRegister()) {
						return (destAddr.equals(lrRegister.getAddress()) ||
							destAddr.equals(lrNewRegister.getAddress()));
					}
					else if (context.isSymbol(destVal) && destAddr.getOffset() == 0) {
						String symbolSpaceName = destAddr.getAddressSpace().getName();
						return (symbolSpaceName.equals(lrRegister.getName()) ||
							symbolSpaceName.equals(lrNewRegister.getName()));
					}
					return false;
				}

				@Override
				public boolean evaluateReference(VarnodeContext context, Instruction instr,
						int pcodeop, Address address, int size, DataType dataType,
						RefType refType) {

					if (address.isExternalAddress()) {
						return true;
					}

					// do super check, then do our own checks
					if (!super.evaluateReference(context, instr, pcodeop, address, size, dataType,
						refType)) {
						return false;
					}

					if (refType.isData()) {
//					// for instruction with more operands than two, will be a dual instruction
//					//   can only do this for single instructions.
//					//  Only way to tell if has a third operand and is not an empty string!
//					List<Object> opRepList = instr.getDefaultOperandRepresentationList(2);
//					if (opRepList != null && opRepList.size() != 0) {
//						return true;
//					}
						// TODO: need to do this better.
						//    Maybe take a look at the register values to tag things on for read/write
						//    all Reads should be in ().  Writes should be in () on the left side.
						if (refType.isWrite()) {
							// goes on first operand
							instr.addOperandReference(0, address, refType, SourceType.ANALYSIS);
							return false;
						}
						else if (refType.isRead()) {
							// goes on second operand
							instr.addOperandReference(1, address, refType, SourceType.ANALYSIS);
							return false;
						}

					}
					// look backward for a good assign instruction that has this as a constant
					// want to markup there if we find one.
					return markupParallelInstruction(instr, refType, address);
				}

				/**
				 * For parallel instruction effects, look back to see if there is a constant in the parallel chain
				 * to match this target address.
				 * 
				 * @return true to just mark it up anywhere, false if we actually put the reference on here.
				 */
				private boolean markupParallelInstruction(Instruction instr, RefType refType,
						Address address) {
					Instruction prevInst = instr;
					int count = 0;
					while (helper.isParallelInstruction(prevInst) && count++ < 5) {
						Address fallFrom = prevInst.getFallFrom();
						if (fallFrom == null)
							break;
						prevInst = program.getListing().getInstructionAt(fallFrom);
						if (prevInst == null)
							break;
						int numOps = prevInst.getNumOperands();

						for (int i = 0; i < numOps; i++) {
							Scalar scalar = prevInst.getScalar(i);
							if (scalar == null)
								continue;
							long unsignedValue = scalar.getUnsignedValue();
							if (unsignedValue == address.getOffset()) {
								// found the value, mark it up
								prevInst.addOperandReference(i, address, refType,
									SourceType.ANALYSIS);
								return false;
							}
						}
					}
					return true;   // just go ahead and mark up the instruction
				}

				@Override
				public boolean evaluateDestination(VarnodeContext context,
						Instruction instruction) {
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
}
