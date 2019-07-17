/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.program.model.address.Address;

import java.math.BigInteger;

/**
 * Class for context configuration information as
 * part of the compiler configuration (CompilerSpec)
 */
public class ContextSetting {
	private Register register;  // Register being set in default context
	private BigInteger value;     // value being set in default context
	private Address startAddr; // Beginning address of context
	private Address endAddr;   // Ending address of context

	public ContextSetting(Register register, BigInteger value, Address startAddr, Address endAddr) {
		this.value = value;
		this.register = register;
		this.startAddr = startAddr;
		this.endAddr = endAddr;
	}

	public Register getRegister() {
		return register;
	}

	public BigInteger getValue() {
		return value;
	}

	public Address getStartAddress() {
		return startAddr;
	}

	public Address getEndAddress() {
		return endAddr;
	}
}
