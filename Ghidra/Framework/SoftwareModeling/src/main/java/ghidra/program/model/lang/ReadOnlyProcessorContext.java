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

/**
 * Read only processor context.  Any sets to the processor context are ignored.
 * 
 */

import java.math.BigInteger;
import java.util.List;

public class ReadOnlyProcessorContext implements ProcessorContext {

	private final ProcessorContextView context;

	public ReadOnlyProcessorContext(ProcessorContextView context) {
		this.context = context;
	}

	@Override
	public Register getBaseContextRegister() {
		return context.getBaseContextRegister();
	}

	@Override
	public Register getRegister(String name) {
		return context.getRegister(name);
	}

	@Override
	public List<Register> getRegisters() {
		return context.getRegisters();
	}

	@Override
	public BigInteger getValue(Register register, boolean signed) {
		return context.getValue(register, signed);
	}

	@Override
	public RegisterValue getRegisterValue(Register register) {
		return context.getRegisterValue(register);
	}

	@Override
	public boolean hasValue(Register register) {
		return context.hasValue(register);
	}

	@Override
	public void setValue(Register register, BigInteger value) {
		//Msg.debug(this, "set reg: " + register.getName() + " = " + value.intValue());
	}

	@Override
	public void setRegisterValue(RegisterValue value) {
		//Msg.debug(this, "set regValue: " + value.getRegister().getName() + " = " + value.getUnsignedValue().intValue());
	}

	@Override
	public void clearRegister(Register register) {
		//Msg.debug(this, "clear reg: " + register.getName());
	}
}
