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
package ghidra.app.plugin.core.assembler.completion;

import java.util.Map;
import java.util.TreeMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ProgramContext;

public class ContextChanges implements DisassemblerContextAdapter {
	private final RegisterValue contextIn;
	final Map<Address, RegisterValue> contextsOut = new TreeMap<>();

	public ContextChanges(RegisterValue contextIn) {
		this.contextIn = contextIn;
	}

	@Override
	public RegisterValue getRegisterValue(Register register) {
		if (register.getBaseRegister() == contextIn.getRegister()) {
			return contextIn.getRegisterValue(register);
		}
		return null;
	}

	@Override
	public void setFutureRegisterValue(Address address, RegisterValue value) {
		RegisterValue current = contextsOut.get(address);
		RegisterValue combined = current == null ? value : current.combineValues(value);
		contextsOut.put(address, combined);
	}

	public void addFlow(ProgramContext progCtx, Address after) {
		contextsOut.put(after, progCtx.getFlowValue(contextIn));
	}
}
