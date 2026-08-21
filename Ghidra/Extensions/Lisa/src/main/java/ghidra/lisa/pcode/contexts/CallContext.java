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
package ghidra.lisa.pcode.contexts;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import it.unive.lisa.program.cfg.statement.call.Call.CallType;

public class CallContext extends PcodeContext {

	private Function callee = null;
	public VarnodeContext left;
	private boolean isTarget;

	public CallContext(PcodeOp op, UnitContext ctx) {
		super(op);
		this.op = op;
		Address address = op.getInput(0).getAddress();
		Function caller = ctx.function();
		left = new SymbolVarnodeContext(address);
		if (address.getAddressSpace().isMemorySpace()) {
			callee = caller.getProgram().getFunctionManager().getFunctionAt(address);
			if (callee != null) {
				left = new SymbolVarnodeContext(callee.getName(), address);
			}
		}
	}

	public String getText() {
		return op.toString();
	}

	public String getCalleeName() {
		return callee == null ? "UNKNOWN" : callee.getName();
	}

	public Function function() {
		return callee;
	}

	public CallType type() {
		if (callee == null || callee.isThunk()) {
			return CallType.UNKNOWN;
		}
		if (op.getInput(0).getAddress().getAddressSpace().isMemorySpace()) {
			return CallType.STATIC;
		}
		return CallType.UNKNOWN;
	}

	public boolean isTarget() {
		return isTarget;
	}

	public void setIsTarget(boolean isTarget) {
		this.isTarget = isTarget;
	}

}
