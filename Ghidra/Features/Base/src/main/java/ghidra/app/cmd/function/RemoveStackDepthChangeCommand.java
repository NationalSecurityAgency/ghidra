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

public class RemoveStackDepthChangeCommand implements Command<Program> {

	private Address address;

	public RemoveStackDepthChangeCommand(Address address) {
		this.address = address;
	}

	@Override
	public boolean applyTo(Program program) {
		return CallDepthChangeInfo.removeStackDepthChange(program, address);
	}

	@Override
	public String getName() {
		return "Remove Stack Depth Change";
	}

	@Override
	public String getStatusMsg() {
		return null;
	}
}
