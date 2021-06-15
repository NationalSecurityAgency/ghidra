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
package ghidra.program.util;

import java.util.Arrays;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.DefaultProgramContext;
import ghidra.program.model.listing.ProgramContext;

abstract public class AbstractProgramContext implements ProgramContext, DefaultProgramContext {
	
	protected Language language;

	protected Register baseContextRegister;

	private boolean hasNonFlowingContext = false;
	private byte[] nonFlowingContextRegisterMask;
	private byte[] flowingContextRegisterMask;

	protected RegisterValue defaultDisassemblyContext;

	protected AbstractProgramContext(Language language) {
		init(language);
	}

	/**
	 * Get underlying language associated with this context and its registers
	 * @return language
	 */
	public Language getLanguage() {
		return language;
	}

	/**
	 * Set those bits in the nonFlowingContextRegisterMask which should not 
	 * flow with context.
	 * @param contextReg context register piece
	 */
	private void initContextBitMasks(Register contextReg) {
		byte[] subMask = contextReg.getBaseMask();
		if (!contextReg.followsFlow()) {
			hasNonFlowingContext = true;
			for (int i = 0; i < nonFlowingContextRegisterMask.length; i++) {
				nonFlowingContextRegisterMask[i] |= subMask[i];
				flowingContextRegisterMask[i] &= ~subMask[i];
			}
		}
		else {
			for (int i = 0; i < flowingContextRegisterMask.length; i++) {
				flowingContextRegisterMask[i] |= subMask[i];
			}
			if (contextReg.hasChildren()) {
				for (Register childReg : contextReg.getChildRegisters()) {
					initContextBitMasks(childReg);
				}
			}
		}
	}

	/**
	 * @return true if one or more non-flowing context registers fields
	 * have been defined within the base processor context register.
	 */
	@Override
	public final boolean hasNonFlowingContext() {
		return hasNonFlowingContext;
	}

	/**
	 * Modify register value to eliminate non-flowing bits
	 * @param value context register value to be modified
	 * @return value suitable for flowing
	 */
	@Override
	public final RegisterValue getFlowValue(RegisterValue value) {
		if (value == null || !hasNonFlowingContext || !value.getRegister().isProcessorContext()) {
			return value;
		}
		return value.clearBitValues(nonFlowingContextRegisterMask);
	}

	/**
	 * Modify register value to only include non-flowing bits
	 * @param value context register value to be modified
	 * @return new value or null if value does not correspond to a context register or
	 * non-flowing context fields have not been defined
	 */
	@Override
	public final RegisterValue getNonFlowValue(RegisterValue value) {
		if (value == null || !hasNonFlowingContext || !value.getRegister().isProcessorContext()) {
			return null;
		}
		return value.clearBitValues(flowingContextRegisterMask);
	}

	/**
	 * Initialize context for the specified language
	 * @param lang processor language for which this context applies
	 */
	protected void init(Language lang) {
		this.language = lang;
		baseContextRegister = lang.getContextBaseRegister();
		if (baseContextRegister == null) {
			baseContextRegister =
				new Register("DEFAULT_CONTEXT", "DEFAULT_CONTEXT", Address.NO_ADDRESS, 4, true, 0);
		}
		defaultDisassemblyContext = new RegisterValue(baseContextRegister);

		nonFlowingContextRegisterMask = baseContextRegister.getBaseMask().clone();
		Arrays.fill(nonFlowingContextRegisterMask, (byte) 0);
		flowingContextRegisterMask = nonFlowingContextRegisterMask.clone();
		initContextBitMasks(baseContextRegister);
	}

	@Override
	public final List<Register> getContextRegisters() {
		return language.getContextRegisters();
	}

	@Override
	public final Register getRegister(String name) {
		return language.getRegister(name);
	}

	@Override
	public final List<String> getRegisterNames() {
		return language.getRegisterNames();
	}

	@Override
	public final List<Register> getRegisters() {
		return language.getRegisters();
	}

	@Override
	public final Register getBaseContextRegister() {
		return baseContextRegister;
	}

	@Override
	public final RegisterValue getDefaultDisassemblyContext() {
		return defaultDisassemblyContext;
	}

	@Override
	public final void setDefaultDisassemblyContext(RegisterValue value) {
		defaultDisassemblyContext = value;
	}

}
