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
package ghidra.app.plugin.assembler.sleigh.sem;

import java.math.BigInteger;
import java.util.List;

import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.DefaultProgramContext;

/**
 * A class that computes the default context for a language, and acts as a pseudo context
 * 
 * This class helps maintain context consistency when performing both assembly and disassembly.
 */
public class AssemblyDefaultContext implements DisassemblerContext, DefaultProgramContext {
	protected final SleighLanguage lang;
	protected final Address at;

	protected AssemblyPatternBlock curctx; // the pseudo context value
	protected AssemblyPatternBlock defctx; // the computed default

	protected final static DbgTimer dbg = DbgTimer.INACTIVE;

	/**
	 * Compute the default context at most addresses for the given language
	 * @param lang the language
	 */
	public AssemblyDefaultContext(SleighLanguage lang) {
		this(lang, null);
	}

	/**
	 * Compute the default context at the given address for the given language
	 * @param lang the language
	 * @param at the address
	 */

	protected AssemblyDefaultContext(SleighLanguage lang, Address at) {
		this.lang = lang;
		this.at = at;
		Register ctxreg = lang.getContextBaseRegister();
		if (null == ctxreg) {
			this.defctx = AssemblyPatternBlock.nop();
			this.curctx = AssemblyPatternBlock.nop();
		}
		else {
			int size = ctxreg.getMinimumByteSize();
			this.defctx = AssemblyPatternBlock.fromLength(size);
			this.curctx = AssemblyPatternBlock.fromLength(size);
		}
		lang.applyContextSettings(this);
	}

	/**
	 * Set the value of the pseudo context register
	 * 
	 * If the provided value has length less than the register, it will be left aligned, and the
	 * remaining bytes will be set to unknown (masked out).
	 * @param val the value of the register
	 */
	public void setContextRegister(byte[] val) {
		curctx = AssemblyPatternBlock.fromBytes(0, val);
	}

	/**
	 * Get the default value of the context register
	 * @return the value as a pattern block for assembly
	 */
	public AssemblyPatternBlock getDefault() {
		return defctx;
	}

	/**
	 * Compute the default value of the context register at the given address
	 * @param addr the addres
	 * @return the value as a pattern block for assembly
	 */
	public AssemblyPatternBlock getDefaultAt(Address addr) {
		return new AssemblyDefaultContext(lang, addr).getDefault();
	}

	@Override
	public void setValue(Register register, BigInteger value) throws ContextChangeException {
		dbg.println("Set " + register + " to " + value);
	}

	@Override
	public void setRegisterValue(RegisterValue value) throws ContextChangeException {
		dbg.println("Set " + value);
	}

	@Override
	public void clearRegister(Register register) throws ContextChangeException {
		dbg.println("Clear " + register);
	}

	@Override
	public Register getBaseContextRegister() {
		return lang.getContextBaseRegister();
	}

	@Override
	public List<Register> getRegisters() {
		return lang.getRegisters();
	}

	@Override
	public Register getRegister(String name) {
		return lang.getRegister(name);
	}

	@Override
	public BigInteger getValue(Register register, boolean signed) {
		if (signed) {
			throw new UnsupportedOperationException();
		}
		if (!register.isProcessorContext()) {
			return null;
		}
		BigInteger res = curctx.toBigInteger(register.getMinimumByteSize());
		if (register.isBaseRegister()) {
			return res;
		}
		throw new UnsupportedOperationException();
	}

	@Override
	public RegisterValue getRegisterValue(Register register) {
		return new RegisterValue(register, getValue(register, false));
	}

	@Override
	public boolean hasValue(Register register) {
		return register.isProcessorContext();
	}

	@Override
	public void setFutureRegisterValue(Address address, RegisterValue value) {
		dbg.println("Set " + value + " at " + address);
	}

	@Override
	public void setFutureRegisterValue(Address fromAddr, Address toAddr, RegisterValue value) {
		dbg.println("Set " + value + " for [" + fromAddr + ":" + toAddr + "]");
	}

	@Override
	public void setDefaultValue(RegisterValue registerValue, Address start, Address end) {
		if (!registerValue.getRegister().isProcessorContext()) {
			return;
		}
		if (at != null && (start.compareTo(at) > 0 || at.compareTo(end) > 0)) {
			return;
		}
		defctx = defctx.combine(AssemblyPatternBlock.fromRegisterValue(registerValue));
		dbg.println("Combining " + registerValue);
		dbg.println("  " + defctx);
	}

	@Override
	public RegisterValue getDefaultValue(Register register, Address address) {
		throw new UnsupportedOperationException();
	}
}
