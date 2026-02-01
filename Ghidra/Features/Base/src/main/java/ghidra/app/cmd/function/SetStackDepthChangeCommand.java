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
package ghidra.app.cmd.function;

import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class SetStackDepthChangeCommand implements Command<Program> {

	private Address address;
	private int stackDepthChange;
	private String errMsg = null;

	public SetStackDepthChangeCommand(Address address, int newStackDepthChange) {
		this.address = address;
		this.stackDepthChange = newStackDepthChange;
	}

	@Override
	public boolean applyTo(Program program) {
		try {
			CallDepthChangeInfo.setStackDepthChange(program, address, stackDepthChange);
			return true;
		}
		catch (DuplicateNameException e) {
			errMsg = e.getMessage();
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			return false;
		}
	}

	@Override
	public String getName() {
		return "Set Stack Depth Change";
	}

	@Override
	public String getStatusMsg() {
		return errMsg;
	}
}
