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
 * Represents a symseg_command structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html">mach-o/loader.h</a> 
 */
public class SymbolCommand extends ObsoleteCommand {
    private int offset;
	private int size;

    static SymbolCommand createSymbolCommand(
            FactoryBundledWithBinaryReader reader) throws IOException,
            MachException {
        SymbolCommand symbolCommand = (SymbolCommand) reader.getFactory().create(SymbolCommand.class);
        symbolCommand.initSymbolCommand(reader);
        return symbolCommand;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public SymbolCommand() {}

	private void initSymbolCommand(FactoryBundledWithBinaryReader reader) throws IOException, MachException {
		initObsoleteCommand(reader);
	}

	public int getOffset() {
		return offset;
	}

	public int getSize() {
		return size;
	}

	@Override
	public String getCommandName() {
		return "symseg_command";
	}
}
