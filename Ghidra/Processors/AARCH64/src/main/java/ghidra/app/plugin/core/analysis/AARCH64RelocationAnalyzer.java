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

import java.util.HashSet;
import java.math.BigInteger;

import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class AARCH64RelocationAnalyzer extends ConstantPropagationAnalyzer {

	private static final String PROCESSOR_NAME = "AARCH64";

	protected static final String CREATE_DATA_REFERENCE_FROM_ADDRESS_RELOCATIONS_OPTION_NAME  =
		"Create data references from address relocations";
	protected static final String CREATE_DATA_REFERENCE_FROM_ADDRESS_RELOCATIONS_OPTION_DESCRIPTION =
		"Create data references from address relocations computed by adrp and add instruction pairs";
	protected static final boolean CREATE_DATA_REFERENCE_FROM_ADDRESS_RELOCATIONS_OPTION_DEFAULT_VALUE = true;

	protected boolean createDataRefsFromAddressRelocationsOption =
		CREATE_DATA_REFERENCE_FROM_ADDRESS_RELOCATIONS_OPTION_DEFAULT_VALUE;
	
	public AARCH64RelocationAnalyzer() {
		super(PROCESSOR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public AddressSet flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {

		final ConstantPropagationContextEvaluator eval;
		if (createDataRefsFromAddressRelocationsOption) {
			HashSet<Address> adrpInstructions = new HashSet<>();

			eval = new ConstantPropagationContextEvaluator(monitor, trustWriteMemOption) {

				@Override
				public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
					String mnemonic = instr.getMnemonicString();

					if (mnemonic.equals("adrp")) {
						adrpInstructions.add(instr.getAddress());
					} else if (mnemonic.equals("add")) {
						// fixup_aarch64_pcrel_adrp_imm21 -> fixup_aarch64_add_imm12
						Register addend = instr.getRegister(1);
						Scalar constantOffset = getScalar(instr, 2);

						if (addend != null && constantOffset != null) {
							BigInteger addendVal = context.getValue(addend, false);
							Address addendProvenanceAddr = context.getLastSetLocation(addend, null);

							if (addendVal != null && adrpInstructions.contains(addendProvenanceAddr)) {
								createDataReference(instr, 0, addendVal.longValue() + constantOffset.getUnsignedValue());
							}
						}
					} else if (mnemonic.equals("adr")) {
						// fixup_aarch64_pcrel_adr_imm21
						Register dest = instr.getRegister(0);
						Scalar constantOffset = getScalar(instr, 1);

						if (dest != null && constantOffset != null) {
							createDataReference(instr, 0, constantOffset.getUnsignedValue());
						}
					}
					return false;
				}

				private Scalar getScalar(Instruction instr, int operandIndex) {
					Object[] scalarObjects = instr.getOpObjects(operandIndex);

					if (scalarObjects != null && scalarObjects.length > 0) {
						Object scalarObject = scalarObjects[0];
						if (scalarObject instanceof Scalar scalar) {
							return scalar;
						}
					}

					return null;
				}

				private void createDataReference(Instruction instr, int opIndex, long offset) {
					AddressSpace space = instr.getMinAddress().getAddressSpace();
					Address addr = space.getTruncatedAddress(offset, true);
					instr.addOperandReference(opIndex, addr, RefType.DATA, SourceType.ANALYSIS);
				}

			};
		} else {
			eval = new ConstantPropagationContextEvaluator(monitor, trustWriteMemOption);
		}

		eval.setTrustWritableMemory(trustWriteMemOption)
		    .setMinSpeculativeOffset(minSpeculativeRefAddress)
		    .setMaxSpeculativeOffset(maxSpeculativeRefAddress)
		    .setMinStoreLoadOffset(minStoreLoadRefAddress)
		    .setCreateComplexDataFromPointers(createComplexDataFromPointers);

		return symEval.flowConstants(flowStart, flowSet, eval, true, monitor);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		super.registerOptions(options, program);
		options.registerOption(CREATE_DATA_REFERENCE_FROM_ADDRESS_RELOCATIONS_OPTION_NAME, createDataRefsFromAddressRelocationsOption,
			null, CREATE_DATA_REFERENCE_FROM_ADDRESS_RELOCATIONS_OPTION_DESCRIPTION);
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
		createDataRefsFromAddressRelocationsOption =
			options.getBoolean(CREATE_DATA_REFERENCE_FROM_ADDRESS_RELOCATIONS_OPTION_NAME, createDataRefsFromAddressRelocationsOption);
	}
}
