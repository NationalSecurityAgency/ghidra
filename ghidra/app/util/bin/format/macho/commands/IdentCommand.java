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
package ghidra.app.util.bin.format.macho.commands;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.macho.MachException;

/**
 * Represents a ident_command structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class IdentCommand extends ObsoleteCommand {

	static IdentCommand createIdentCommand(FactoryBundledWithBinaryReader reader)
			throws IOException, MachException {
		IdentCommand identCommand = (IdentCommand) reader.getFactory().create(IdentCommand.class);
		identCommand.initIdentCommand(reader);
		return identCommand;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public IdentCommand() {
	}

	private void initIdentCommand(FactoryBundledWithBinaryReader reader)
			throws IOException, MachException {
		initObsoleteCommand(reader);
	}

	@Override
	public String getCommandName() {
		return "ident_command";
	}
}
