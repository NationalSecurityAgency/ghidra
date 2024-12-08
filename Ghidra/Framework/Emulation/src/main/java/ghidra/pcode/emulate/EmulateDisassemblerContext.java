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
package ghidra.pcode.emulate;

import java.math.BigInteger;
import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.util.ProgramContextImpl;

public class EmulateDisassemblerContext implements DisassemblerContext {

	private final Language language;
	private final Map<Address, RegisterValue> futureContextMap;
	private final Register contextReg;

	private RegisterValue contextRegValue;
	private byte[] flowingContextRegisterMask;
	private boolean hasNonFlowingContext;

	EmulateDisassemblerContext(Language language) {
		this.language = language;
		this.contextReg = language.getContextBaseRegister();
		this.futureContextMap = new HashMap<Address, RegisterValue>();
		initContext();
	}

	public EmulateDisassemblerContext(Language language, RegisterValue initialContextValue) {
		this(language);
		this.contextRegValue = initialContextValue;
	}

	@Override
	public Register getBaseContextRegister() {
		return contextReg;
	}

	public RegisterValue getCurrentContextRegisterValue() {
		if (contextRegValue == null) {
			return null;
		}
		return new RegisterValue(contextRegValue.getRegister(), contextRegValue.toBytes());
	}

	public void setCurrentAddress(Address addr) {

		if (contextReg == Register.NO_CONTEXT) {
			return;
		}
		RegisterValue partialValue = null;
		if (contextRegValue != null && contextRegValue.getRegister() != contextReg) {
			if (contextRegValue.getRegister().getBaseRegister() == contextReg) {
				partialValue = contextRegValue;
			}
			contextRegValue = null;
		}
		if (contextRegValue == null) {
			ProgramContextImpl defaultContext = new ProgramContextImpl(language);
			language.applyContextSettings(defaultContext);
			contextRegValue = defaultContext.getDefaultValue(contextReg, addr);
			if (contextRegValue == null) {
				contextRegValue = new RegisterValue(contextReg);
			}
			if (partialValue != null) {
				contextRegValue = contextRegValue.combineValues(partialValue);
			}
		}
		if (hasNonFlowingContext) {
			byte[] contextBytes = contextRegValue.toBytes();
			int valMaskLen = contextBytes.length >> 1;

			for (int i = 0; i < valMaskLen; i++) {
				contextBytes[i] &= flowingContextRegisterMask[i]; // clear non-flowing mask bits
				contextBytes[valMaskLen + i] &= flowingContextRegisterMask[i]; // clear non-flowing value bits
			}
			contextRegValue = new RegisterValue(contextReg, contextBytes);
		}

		// WARNING: futureContextMap could accumulate a significant amount of context if it never gets purged
		// although we may need it later (e.g., end-of-loop)
		RegisterValue newContext = futureContextMap.get(addr);
		if (newContext != null) {
			contextRegValue = contextRegValue.combineValues(newContext);
		}
	}

	private void initContext() {
		if (contextReg == Register.NO_CONTEXT) {
			return;
		}
		flowingContextRegisterMask = contextReg.getBaseMask().clone();
		Arrays.fill(flowingContextRegisterMask, (byte) 0);
		initContextBitMasks(contextReg);
	}

	/**
	 * Set those bits in the nonFlowingContextRegisterMask which should not 
	 * flow with context.
	 * @param reg context register piece
	 */
	private void initContextBitMasks(Register reg) {
		byte[] subMask = reg.getBaseMask();
		if (!reg.followsFlow()) {
			hasNonFlowingContext = true;
			for (int i = 0; i < flowingContextRegisterMask.length; i++) {
				flowingContextRegisterMask[i] &= ~subMask[i];
			}
		}
		else {
			for (int i = 0; i < flowingContextRegisterMask.length; i++) {
				flowingContextRegisterMask[i] |= subMask[i];
			}
			if (reg.hasChildren()) {
				for (Register childReg : reg.getChildRegisters()) {
					initContextBitMasks(childReg);
				}
			}
		}
	}

	@Override
	public void clearRegister(Register register) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Register getRegister(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public RegisterValue getRegisterValue(Register register) {
		if (!register.isProcessorContext()) {
			throw new UnsupportedOperationException();
		}
		if (register.equals(contextReg)) {
			return contextRegValue;
		}
		return new RegisterValue(register, contextRegValue.toBytes());
	}

	@Override
	public List<Register> getRegisters() {
		throw new UnsupportedOperationException();
	}

	@Override
	public BigInteger getValue(Register register, boolean signed) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasValue(Register register) {
		return true;
	}

	@Override
	public void setRegisterValue(RegisterValue value) {
		Register reg = value.getRegister();
		if (!reg.isProcessorContext()) {
			throw new UnsupportedOperationException();
		}
		if (contextRegValue == null) {
			contextRegValue = value.getBaseRegisterValue();
		}
		else {
			contextRegValue = contextRegValue.combineValues(value);
		}
	}

	@Override
	public void setValue(Register register, BigInteger value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setFutureRegisterValue(Address address, RegisterValue value) {
		Register reg = value.getRegister();
		if (!reg.isProcessorContext()) {
			throw new UnsupportedOperationException();
//			Msg.warn(this, "Setting register " + reg.getName() + " during emulator disassembly ignored!");
//			return;
		}
		RegisterValue registerValue = futureContextMap.get(address);
		if (registerValue != null) {
			value = registerValue.combineValues(value);
		}
		futureContextMap.put(address, value);
	}

	@Override
	public void setFutureRegisterValue(Address fromAddr, Address toAddr, RegisterValue value) {
		throw new UnsupportedOperationException();
	}
}
