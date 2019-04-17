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
package ghidra.app.cmd.label;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class PinSymbolCmd implements Command {

	private Address addr;
	private String name;
	private boolean pin;
	private String message;

	public PinSymbolCmd(Address addr, String name, boolean pin) {
		this.addr = addr;
		this.name = name;
		this.pin = pin;
	}

	@Override
	public boolean applyTo(DomainObject obj) {
		SymbolTable symbolTable = ((Program) obj).getSymbolTable();
		Symbol symbol = symbolTable.getGlobalSymbol(name, addr);
		if (symbol == null) {
			message = "Could not find symbol named " + name + " at address " + addr;
			return false;
		}
		symbol.setPinned(pin);
		return true;
	}

	@Override
	public String getStatusMsg() {
		return message;
	}

	@Override
	public String getName() {
		return "Set Pinned on " + name;
	}

}
