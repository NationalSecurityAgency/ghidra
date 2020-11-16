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
import java.util.List;

/**
 * Defines the interface for an object containing the state
 * of all processor registers relative to a specific address.
 */
public interface ProcessorContextView {

	/**
	 * @return the base processor context register or null if one
	 * has not been defined
	 */
	public Register getBaseContextRegister();

	/**
	 * Returns all the Registers for the processor as an unmodifiable list
	 * @return all the Registers for the processor
	 */
	public List<Register> getRegisters();

	/**
	 * Get a Register given the name of a register
	 *
	 * @param name the name of the register.
	 * @return The register with the given name.
	 */
	public Register getRegister(String name);

	/**
	 * Get the contents of a processor register as a BigInteger object
	 * @param register register to get the value for
	 * @return a BigInteger object containing the value of the register if a value exists,
	 * otherwise null.
	 */
	public BigInteger getValue(Register register, boolean signed);

	/**
	 * Get the RegisterValue for the given register.
	 * @param register register to get the value for
	 * @return RegisterValue object containing the value of the register if a value exists,
	 * otherwise null.
	 */
	public RegisterValue getRegisterValue(Register register);

	/**
	 * Returns true if a value is defined for the given register.
	 * @param register the register to check for a value.
	 * @return true if the given register has a value.
	 */
	public boolean hasValue(Register register);

	public static String dumpContextValue(RegisterValue value, String indent) {
		StringBuilder buf = new StringBuilder();
		dumpContextValue(value, indent, buf);
		return buf.toString();
	}

	public static void dumpContextValue(RegisterValue value, String indent, StringBuilder buf) {
		if (indent == null) {
			indent = "";
		}
		Register baseReg = value.getRegister();
		int baseRegSize = baseReg.getMinimumByteSize() * 8;
		for (Register reg : baseReg.getChildRegisters()) {
			RegisterValue childValue = value.getRegisterValue(reg);
			if (childValue.hasAnyValue()) {
				BigInteger v = childValue.getUnsignedValueIgnoreMask();
				int msb = baseRegSize - reg.getLeastSignificatBitInBaseRegister() - 1;
				int lsb = msb - reg.getBitLength() + 1;
				if (buf.length() != 0) {
					buf.append("\n");
				}
				buf.append(indent + reg.getName() + "(" + lsb + "," + msb + ") = 0x" +
					Long.toHexString(v.longValue()));
				if (reg.hasChildren()) {
					dumpContextValue(childValue, indent + "   ", buf);
				}
			}
		}
	}

}
