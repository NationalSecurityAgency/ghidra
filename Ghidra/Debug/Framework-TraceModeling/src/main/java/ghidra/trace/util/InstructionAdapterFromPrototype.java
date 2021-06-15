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
package ghidra.trace.util;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.UniqueAddressFactory;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionPcodeOverride;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;

public interface InstructionAdapterFromPrototype extends Instruction {
	default String getFullString() {
		StringBuilder sb = new StringBuilder();
		sb.append(getMnemonicString());

		int n = getNumOperands();
		String sep = getSeparator(0);
		if (sep != null || n != 0) {
			sb.append(' ');
		}
		if (sep != null) {
			sb.append(sep);
		}

		for (int i = 0; i < n; i++) {
			sb.append(getDefaultOperandRepresentation(i));
			sep = getSeparator(i + 1);
			if (sep != null) {
				sb.append(sep);
			}
		}
		return sb.toString();
	}

	@Override
	default String getMnemonicString() {
		return getPrototype().getMnemonic(getInstructionContext());
	}

	@Override
	default int getNumOperands() {
		return getPrototype().getNumOperands();
	}

	@Override
	default Address getAddress(int opIndex) {
		if (opIndex < 0) {
			return null;
		}
		InstructionPrototype prototype = getPrototype();
		InstructionContext context = getInstructionContext();
		int opType = prototype.getOpType(opIndex, context);
		if (OperandType.isAddress(opType)) {
			return prototype.getAddress(opIndex, context);
		}
		return null;
	}

	@Override
	default Scalar getScalar(int opIndex) {
		return getPrototype().getScalar(opIndex, getInstructionContext());
	}

	@Override
	default Register getRegister(int opIndex) {
		return getPrototype().getRegister(opIndex, getInstructionContext());
	}

	@Override
	default Object[] getOpObjects(int opIndex) {
		return getPrototype().getOpObjects(opIndex, getInstructionContext());
	}

	@Override
	default Object[] getInputObjects() {
		return getPrototype().getInputObjects(getInstructionContext());
	}

	@Override
	default Object[] getResultObjects() {
		return getPrototype().getResultObjects(getInstructionContext());
	}

	@Override
	default String getDefaultOperandRepresentation(int opIndex) {
		List<Object> opList = getDefaultOperandRepresentationList(opIndex);
		if (opList == null) {
			return "<UNSUPPORTED>";
		}
		StringBuilder sb = new StringBuilder();
		for (Object opElem : opList) {
			if (opElem instanceof Address) {
				Address opAddr = (Address) opElem;
				sb.append("0x");
				sb.append(opAddr.toString(false));
			}
			else {
				sb.append(opElem.toString());
			}
		}
		return sb.toString();
	}

	@Override
	default List<Object> getDefaultOperandRepresentationList(int opIndex) {
		return getPrototype().getOpRepresentationList(opIndex, getInstructionContext());
	}

	@Override
	default String getSeparator(int opIndex) {
		return getPrototype().getSeparator(opIndex, getInstructionContext());
	}

	@Override
	default int getOperandType(int opIndex) {
		return getPrototype().getOpType(opIndex, getInstructionContext());
	}

	@Override
	default RefType getOperandRefType(int opIndex) {
		InstructionPrototype prototype = getPrototype();
		Language language = prototype.getLanguage();
		InstructionPcodeOverride override = new InstructionPcodeOverride(this);
		// TODO: addressFactory may need to be from program/trace (so it has cSpec)
		UniqueAddressFactory uniqueFactory =
			new UniqueAddressFactory(language.getAddressFactory(), language);
		return prototype.getOperandRefType(opIndex, getInstructionContext(), override,
			uniqueFactory);
	}

	@Override
	default int getDefaultFallThroughOffset() {
		return getPrototype().getFallThroughOffset(getInstructionContext());
	}

	@Override
	default PcodeOp[] getPcode() {
		return getPcode(false);
	}

	@Override
	default PcodeOp[] getPcode(boolean includeOverrides) {
		if (!includeOverrides) {
			return getPrototype().getPcode(getInstructionContext(), null, null);
		}
		InstructionPrototype prototype = getPrototype();
		Language language = prototype.getLanguage();
		InstructionPcodeOverride override = new InstructionPcodeOverride(this);
		UniqueAddressFactory uniqueFactory =
			new UniqueAddressFactory(language.getAddressFactory(), language);
		return prototype.getPcode(getInstructionContext(), override, uniqueFactory);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * NOTE: This assumes operand pcode is not affected by flow override
	 */
	@Override
	default PcodeOp[] getPcode(int opIndex) {
		return getPrototype().getPcode(getInstructionContext(), opIndex);
	}

	@Override
	default int getDelaySlotDepth() {
		return getPrototype().getDelaySlotDepth(getInstructionContext());
	}

	@Override
	default boolean isInDelaySlot() {
		return getPrototype().isInDelaySlot();
	}
}
