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
package ghidra.app.plugin.core.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;

import java.math.BigInteger;

class RegisterContextBuilder {

	private Program program;
	private Register reg;
	private boolean isBitRegister;
	private BigInteger mask; // specifies allowed bits, other bits will be ignored and cleared

	private Address setAddr;
	private BigInteger value;

	/**
	 * 
	 * @param program
	 * @param reg tracked register (may not be the context-register)
	 * @param isBitRegister
	 */
	RegisterContextBuilder(Program program, Register reg, boolean isBitRegister) {
		this(program, reg, isBitRegister ? 1 : 0);
		this.isBitRegister = isBitRegister;
	}

	RegisterContextBuilder(Program program, Register reg, long mask) {
		if (reg.isProcessorContext()) {
			throw new IllegalArgumentException("reg may not be processor context register");
		}
		this.program = program;
		this.reg = reg;
		this.isBitRegister = false;
		this.mask = mask != 0 ? BigInteger.valueOf(mask) : null;
	}

	/**
	 * Set the register value to an unknown state.
	 */
	void setValueUnknown() {
		value = null;
		setAddr = null;
	}

	/**
	 * Set the point at which the register value has changed.
	 * If the previous value setting should be saved, the writeValue
	 * method should be invoked first.
	 * @param instr set instruction or first instruction of range.
	 * @param newValue register value
	 * @param valueAssumed if false the value set point will be at the fall-through
	 * address of the current instruction (normal set operation), if true the value
	 * assumed at the start of the specified instr.  If false and instr does not
	 * have a fall-through, this method has not affect.
	 */
	void setValueAt(Instruction instr, BigInteger newValue, boolean valueAssumed) {
		if (instr == null || newValue == null) {
			throw new IllegalArgumentException("instr and newValue required");
		}
		setAddr = valueAssumed ? instr.getMinAddress() : instr.getFallThrough();
		if (setAddr != null) {
			value = newValue;
			if (mask != null) {
				value = value.and(mask);
			}
		}
	}

	/**
	 * Set the point at which the register value has changed.
	 * If the previous value setting should be saved, the writeValue
	 * method should be invoked first.
	 * @param instr set instruction or first instruction of range.
	 * @param newValue register value
	 * @param valueAssumed if false the value set point will be at the fall-through
	 * address of the current instruction (normal set operation), if true the value
	 * assumed at the start of the specified instr.  If false and instr does not
	 * have a fall-through, this method has not affect.
	 */
	void setValueAt(Instruction instr, long newValue, boolean assumed) {
		setValueAt(instr, BigInteger.valueOf(newValue), assumed);
	}

	/**
	 * Set an assumed register value at the specified instr using
	 * the register value at valueFrom.  If overwrite is true and a 
	 * context value is not found at valueFrom, the value state will revert 
	 * to unknown.
	 * @param instr first instruction of range
	 * @param valueFrom point from which existing register value should
	 * be read from program context.
	 * @param overwrite this method will take not action and return false if 
	 * this parameter is false and and a context value has previously been set,
	 * otherwise an attempt will be made to overwrite the current value state.
	 * @return true if value was set, otherwise false.
	 */
	boolean setValueAt(Instruction instr, Address valueFrom, boolean overwrite) {
		if (value == null || overwrite) {
			BigInteger val = program.getProgramContext().getValue(reg, valueFrom, false);
			if (val != null) {
				setValueAt(instr, val, true);
				return true;
			}
			setValueUnknown();
		}
		return false;
	}

	/**
	 * Returns true if the register value has been set.
	 */
	boolean hasValue() {
		return value != null;
	}

	/**
	 * Returns current register value or null if it has not been set.
	 */
	BigInteger value() {
		return value;
	}

	/**
	 * Returns current register value.
	 * @throws RuntimeException if value is unknown or has not been set.
	 * The hasValue should be used to ensure that a value has been set.
	 */
	long longValue() throws RuntimeException {
		if (value != null) {
			return value.longValue();
		}
		throw new RuntimeException();
	}

	/**
	 * Write the current value out to the program context if the register
	 * has been set.  If the value has not been set and is unknown, the method
	 * will have no effect.
	 * @param rangeEnd end of value range (inclusive)
	 * @throws ContextChangeException if attempt is made to write context register value
	 * where an instruction already exists.
	 */
	boolean writeValue(Address rangeEnd) {
		if (setAddr != null && setAddr.compareTo(rangeEnd) < 0) {

//boolean overwrite = (program.getProgramContext().getValue(reg, setAddr, false) != null);				
//String setStr = setAddrAssumed ? "" : " *SET*";
//String owStr = overwrite ? " ???" : "";
			try {
				program.getProgramContext().setValue(reg, setAddr, rangeEnd, value);
			}
			catch (ContextChangeException e) {
				// reg is never processor context register
			}
			return true;
		}
		return false;
	}

	/**
	 * The specified instr has set the specified bit for this context reg.
	 * If setting fails the value will be left in an unknown state.
	 * @param instr instruction which has made the bit modification
	 * @param bit the bit to be set.
	 * @param rightShiftFactor value will be subtracted from specified bit to determine actual bit
	 * to be set. 
	 * @return false if setting not possible (caused by instr not having a fall-through or
	 * this is a multi-bit register without a previous value setting, or bit is null). 
	 */
	public boolean setBitAt(Instruction instr, Scalar bit, int rightShiftFactor) {
		if (bit != null) {
			int bitNum = (int) bit.getUnsignedValue() - rightShiftFactor;
			return setBitAt(instr, bitNum);
		}
		value = null;
		return false;
	}

	/**
	 * The specified instr has set the specified bit for this context reg.
	 * If setting fails the value will be left in an unknown state.
	 * @param instr instruction which has made the bit modification
	 * @param bit the bit to be set.
	 * @return false if setting not possible (caused by instr not having a fall-through or
	 * this is a multi-bit register without a previous value setting, or bit is null). 
	 */
	public boolean setBitAt(Instruction instr, int bit) {
		if (isBitRegister || value != null) {
			setAddr = instr.getFallThrough();
			if (setAddr != null) {
				if (value == null) {
					value = BigInteger.valueOf(0);
				}
				value = value.setBit(bit);
				if (mask != null) {
					value = value.and(mask);
				}
				return true;
			}
		}
		value = null;
		return false;
	}

	/**
	 * The specified instr has cleared the specified bit for this context reg.
	 * If setting fails the value will be left in an unknown state.
	 * @param instr instruction which has made the bit modification
	 * @param bit the bit to be cleared.
	 * @param rightShiftFactor value will be subtracted from specified bit to determine actual bit
	 * to be cleared. 
	 * @return false if clear not possible (caused by instr not having a fall-through or
	 * this is a multi-bit register without a previous value setting, or bit is null). 
	 */
	public boolean clearBitAt(Instruction instr, Scalar bit, int rightShiftFactor) {
		if (bit != null) {
			int bitNum = (int) bit.getUnsignedValue() - rightShiftFactor;
			return clearBitAt(instr, bitNum);
		}
		value = null;
		return false;
	}

	/**
	 * The specified instr has cleared the specified bit for this context reg.
	 * If setting fails the value will be left in an unknown state.
	 * @param instr instruction which has made the bit modification
	 * @param bit the bit to be cleared.
	 * @return false if clear not possible (caused by instr not having a fall-through or
	 * this is a multi-bit register without a previous value setting, or bit is null). 
	 */
	public boolean clearBitAt(Instruction instr, int bit) {
		if (isBitRegister || value != null) {
			setAddr = instr.getFallThrough();
			if (setAddr != null) {
				if (value == null) {
					value = BigInteger.valueOf(0);
				}
				else {
					value = value.clearBit(bit);
				}
				return true;
			}
		}
		value = null;
		return false;
	}
}
