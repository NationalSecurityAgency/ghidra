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
package ghidra.program.model.lang;

import java.math.BigInteger;
import java.util.*;

/**
 * An implementation of processor context which contains the state of all
 * processor registers.
 * <br>
 * Note that the ContextChangeException will never be thrown by this implementation
 * of Processor
 */
public final class ProcessorContextImpl implements ProcessorContext {
	Map<Register, byte[]> values = new HashMap<Register, byte[]>();
	Language language;

//	public ProcessorContextImpl(ProcessorContext context) {
//		this(context.getRegisters());
//		for (Register register : registers) {
//			if (!register.isBaseRegister()) {
//				continue;
//			}
//			if (register.isProcessorContext()) {
//				baseContextRegister = register;
//			}
//			RegisterValue value = context.getRegisterValue(register);
//			if (value != null) {
//				setRegisterValue(value);
//			}
//		}
//	}

	public ProcessorContextImpl(Language language) {
		this.language = language;
	}

	@Override
	public Register getBaseContextRegister() {
		return language.getContextBaseRegister();
	}

	@Override
	public Register getRegister(String name) {
		return language.getRegister(name);
	}

	@Override
	public List<Register> getRegisters() {
		return language.getRegisters();
	}

	@Override
	public RegisterValue getRegisterValue(Register register) {
		byte[] bytes = values.get(register.getBaseRegister());
		if (bytes == null) {
			return null;
		}

		return new RegisterValue(register, bytes);
	}

	@Override
	public BigInteger getValue(Register register, boolean signed) {
		byte[] bytes = values.get(register.getBaseRegister());
		if (bytes == null) {
			return null;
		}

		RegisterValue value = new RegisterValue(register, bytes);
		return signed ? value.getSignedValue() : value.getUnsignedValue();
	}

	@Override
	public boolean hasValue(Register register) {
		return getValue(register, false) != null;
	}

	@Override
	public void setValue(Register register, BigInteger value) {
		setRegisterValue(new RegisterValue(register, value));
	}

	@Override
	public void setRegisterValue(RegisterValue value) {
		Register baseRegister = value.getRegister().getBaseRegister();
		byte[] currentBytes = values.get(baseRegister);
		if (currentBytes != null) {
			RegisterValue currentValue = new RegisterValue(baseRegister, currentBytes);

			RegisterValue combinedValue = currentValue.combineValues(value);
			values.put(baseRegister, combinedValue.toBytes());
		}
		else {
			values.put(baseRegister, value.toBytes());
		}
	}

	@Override
	public void clearRegister(Register register) {
		Register baseRegister = register.getBaseRegister();
		byte[] currentBytes = values.remove(baseRegister);
		if (currentBytes != null) {
			RegisterValue currentValue = new RegisterValue(baseRegister, currentBytes);
			currentValue = currentValue.clearBitValues(register.getBaseMask());
			if (currentValue.hasAnyValue()) {
				values.put(baseRegister, currentValue.toBytes());
			}
		}
	}

	public void clearAll() {
		values.clear();
	}

}
