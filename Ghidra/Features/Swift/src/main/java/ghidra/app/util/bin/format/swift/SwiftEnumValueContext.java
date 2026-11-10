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
package ghidra.app.util.bin.format.swift;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;

/**
 * Binds supported Swift layouts to explicitly typed LOADs in one decompilation context.
 * A caller must establish that the selected LOAD reads a valid value of the supplied type in
 * this invocation. Descriptor proximity or a type name alone does not establish that premise.
 * No declarations or program annotations are changed. Native analysis additionally matches
 * the LOAD's SSA result and any required branch edge before using the contract.
 */
public final class SwiftEnumValueContext {

	private SwiftEnumValueContext() {
	}

	/**
	 * @param owner function containing the typed LOAD
	 * @param loadAddress instruction reading the valid enum storage
	 * @param descriptor exact enum descriptor identity
	 * @param typedContextEvidence audit description of the independently established type binding
	 * @return a request-local contract, or empty for unsupported metadata or an unmatched LOAD
	 */
	public static Optional<ValueDomainConstraint> noPayloadLoad(Function owner,
			Address loadAddress, Address descriptor, String typedContextEvidence) {
		requireContext(owner, typedContextEvidence);
		SwiftEnumDomainResolver resolver = new SwiftEnumDomainResolver(owner.getProgram());
		return resolver.resolveNoPayload(descriptor)
			.filter(domain -> matchesLoad(owner, loadAddress, domain.getStorageSize()))
			.map(domain -> new ValueDomainConstraint(owner.getEntryPoint(), loadAddress,
				domain.getStorageSize(), 0, domain.getCaseCount() - 1, descriptor,
				"Swift no-payload enum; " + typedContextEvidence));
	}

	/**
	 * The type premise applies only on the indicated original raw p-code branch outcome. The native
	 * consumer must prove that edge is required to reach a use and its condition refers to this LOAD.
	 *
	 * @param owner function containing the LOAD and required edge
	 * @param loadAddress instruction reading the valid enum storage
	 * @param metadata exact payload enum metadata identity
	 * @param ordinal selected payload's declaration-order ordinal
	 * @param guardAddress instruction of the required conditional branch
	 * @param guardTrue required outcome of the original raw CBRANCH condition, before optimization
	 * @param typedContextEvidence audit description of the independently established type binding
	 * @return a request-local contract, or empty when the layout or instructions are unsupported
	 */
	public static Optional<ValueDomainConstraint> payloadLoad(Function owner, Address loadAddress,
			Address metadata, int ordinal, Address guardAddress, boolean guardTrue,
			String typedContextEvidence) {
		requireContext(owner, typedContextEvidence);
		if (!matchesOpcode(owner, guardAddress, PcodeOp.CBRANCH)) {
			return Optional.empty();
		}
		SwiftEnumDomainResolver resolver = new SwiftEnumDomainResolver(owner.getProgram());
		return resolver.resolvePayload(metadata, ordinal)
			.filter(domain -> matchesLoad(owner, loadAddress, domain.getStorageSize()))
			.map(domain -> new ValueDomainConstraint(owner.getEntryPoint(), loadAddress,
				domain.getStorageSize(), domain.getEncodedFirst(), domain.getEncodedLast(),
				domain.getDescriptorAddress(), "Swift payload witnesses sha256=" +
					domain.getEvidenceSha256() + "; " + typedContextEvidence,
				guardAddress, guardTrue));
	}

	private static void requireContext(Function owner, String evidence) {
		Objects.requireNonNull(owner);
		if (evidence == null || evidence.isBlank()) {
			throw new IllegalArgumentException("An explicit typed invocation context is required");
		}
	}

	private static boolean matchesLoad(Function owner, Address address, int size) {
		PcodeOp op = uniqueOp(owner, address, PcodeOp.LOAD);
		return op != null && op.getOutput() != null && op.getOutput().getSize() == size;
	}

	private static boolean matchesOpcode(Function owner, Address address, int opcode) {
		return uniqueOp(owner, address, opcode) != null;
	}

	private static PcodeOp uniqueOp(Function owner, Address address, int opcode) {
		if (address == null || !address.isMemoryAddress() || !owner.getBody().contains(address)) {
			return null;
		}
		Instruction instruction = owner.getProgram().getListing().getInstructionAt(address);
		if (instruction == null) {
			return null;
		}
		PcodeOp match = null;
		for (PcodeOp op : instruction.getPcode()) {
			if (op.getOpcode() != opcode) {
				continue;
			}
			if (match != null) {
				return null;
			}
			match = op;
		}
		return match;
	}
}
