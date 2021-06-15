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
package ghidra.app.plugin.core.debug.mapping;

import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.plugin.core.debug.register.RegisterTypeInfo;
import ghidra.dbg.target.TargetRegister;
import ghidra.dbg.util.ConversionUtils;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;

/**
 * A mapper which can convert register names and values from trace to target and vice versa.
 * 
 * <P>
 * As a general principle, and as a means of avoiding aliasing within caches, the debugger transfers
 * register values to and from the target using its base registers only. This has its own drawbacks,
 * but I find it preferable to requiring register caches (which are implemented generically) to know
 * the aliasing structure of the register set. That principle could change if the base-register-only
 * scheme becomes unwieldy. That said, a register mapper can map to non-base registers on target,
 * but the trace side of the mapping must deal exclusively in base registers.
 */
public interface DebuggerRegisterMapper {
	/**
	 * Get a target register (name) by string
	 * 
	 * @param name the name of the register as a string
	 * @return the register description (name) on target
	 */
	TargetRegister getTargetRegister(String name);

	/**
	 * Get a trace register (name) by string
	 * 
	 * @param name the name of the register as a string
	 * @return the register description (as defined by the Ghidra language) in the trace
	 */
	Register getTraceRegister(String name);

	/**
	 * Convert a register value to a string-byte-array entry suitable for the debug API
	 * 
	 * <P>
	 * Byte arrays for the debug model API are always big-endian, no matter the target architecture.
	 * 
	 * @param registerValue the register value
	 * @return the entry
	 */
	default Entry<String, byte[]> traceToTarget(RegisterValue registerValue) {
		Register lReg = registerValue.getRegister();
		if (!lReg.isBaseRegister()) {
			throw new IllegalArgumentException();
		}
		TargetRegister tReg = traceToTarget(lReg);
		if (tReg == null) {
			return null;
		}
		return Map.entry(tReg.getIndex(), ConversionUtils
				.bigIntegerToBytes(lReg.getMinimumByteSize(), registerValue.getUnsignedValue()));
	}

	/**
	 * Convert a collection of register values to a string-byte-array map suitable for the debug API
	 * 
	 * @param registerValues the collection of values
	 * @return the map
	 */
	default Map<String, byte[]> traceToTarget(Collection<RegisterValue> registerValues) {
		Map<String, byte[]> result = new LinkedHashMap<>();
		for (RegisterValue rv : registerValues) {
			Entry<String, byte[]> entry = traceToTarget(rv);
			if (entry != null) {
				result.put(entry.getKey(), entry.getValue());
			}
		}
		return result;
	}

	/**
	 * Convert a trace register name to a target register name
	 * 
	 * @param register the trace register
	 * @return the target register
	 */
	TargetRegister traceToTarget(Register register);

	/**
	 * Convert a target register name and byte array value into a trace register value
	 * 
	 * @param tRegName the name of the target register as a string
	 * @param value the value of the target register
	 * @return the converted register value suitable for trace storage
	 */
	default RegisterValue targetToTrace(String tRegName, byte[] value) {
		TargetRegister tReg = getTargetRegister(tRegName);
		if (tReg == null) {
			return null;
		}
		return targetToTrace(tReg, value);
	}

	/**
	 * Convert a target register name and byte array value into a trace register value
	 * 
	 * @param tReg the name of the target register
	 * @param value the value of the target register
	 * @return the converted register value suitable for trace storage
	 */
	default RegisterValue targetToTrace(TargetRegister tReg, byte[] value) {
		if (value == null) {
			return null;
		}
		Register lReg = targetToTrace(tReg);
		if (lReg == null) {
			return null;
		}
		BigInteger big = new BigInteger(1, value);
		return new RegisterValue(lReg, big);
	}

	/**
	 * Convert a string-byte-value map to a map of trace register values
	 * 
	 * @param values the target values
	 * @return the trace values
	 */
	default Map<Register, RegisterValue> targetToTrace(Map<String, byte[]> values) {
		Map<Register, RegisterValue> result = new LinkedHashMap<>();
		for (Map.Entry<String, byte[]> ent : values.entrySet()) {
			RegisterValue rv = targetToTrace(ent.getKey(), ent.getValue());
			if (rv != null) {
				result.put(rv.getRegister(), rv);
			}
		}
		return result;
	}

	/**
	 * Convert a target register name to a trace register name
	 * 
	 * @param tReg the target register name
	 * @return the trace register name (as defined by the Ghidra language)
	 */
	Register targetToTrace(TargetRegister tReg);

	/**
	 * Get suggested type information for a given trace register
	 * 
	 * <P>
	 * TODO: The recorder should apply this type when recording register values
	 * 
	 * @param lReg the name of the trace register
	 * @return the default type information
	 */
	RegisterTypeInfo getDefaultTypeInfo(Register lReg);

	/**
	 * Get the (base) registers on target that can be mapped
	 * 
	 * @return the collection of base registers
	 */
	Set<Register> getRegistersOnTarget();

	/**
	 * The recorder is informing this mapper of a new target register
	 * 
	 * <P>
	 * The mapper should check that the given register is in its scope.
	 * 
	 * @param register the new register
	 */
	void targetRegisterAdded(TargetRegister register);

	/**
	 * The recorder is informing this mapper of a removed target register
	 * 
	 * <P>
	 * This may seem impossible, but it can happen on architectures that support native emulation,
	 * and the debugger changes its register definitions (mid-execution) accordingly. One important
	 * example is WoW64 when switching between the 32-bit executable image and 64-bit system
	 * libraries. The 64-bit registers are not accessible when the processor is in 32-bit mode.
	 * 
	 * <P>
	 * The mapper should check that the given register is/was in its scope.
	 * 
	 * @param register the old register
	 */
	void targetRegisterRemoved(TargetRegister register);
}
