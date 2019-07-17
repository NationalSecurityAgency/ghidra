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
//Renames default labels in a selected region, using
//a user-defined stub and a one-up naming convention.
//@category Symbol

import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;

public class AutoRenameLabelsScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (currentSelection == null || currentSelection.isEmpty()) {
            println("No selection exists.");
            return;
        }

        String base = askString("Auto Rename Labels", "Enter label base name:");
        if (base == null) {
            println("No base value entered.");
            return;
        }

        int num = 1;

        AddressSetView view = currentSelection;
        if ((view == null) || (view.isEmpty())) return;

        // Obtain the symbol table and listing from program
        SymbolTable symbolTable = currentProgram.getSymbolTable();

        // Get the addresses in the set.
        AddressIterator it = view.getAddresses(true);
        
        CompoundCmd cmd = new CompoundCmd("Auto Rename Labels");
        while(it.hasNext()) {
            Address address = it.next();
        	Symbol[] symbols = symbolTable.getSymbols(address);            
            Symbol defaultSymbol = getDynamicSymbol( symbols );
            if ( defaultSymbol != null ) {
                cmd.add(new RenameLabelCmd(address, null, base+num++, SourceType.USER_DEFINED));
            }
        }
        if (cmd.size() > 0) {
            if (!cmd.applyTo(currentProgram)) {
            	String msg = cmd.getStatusMsg();
            	if (msg != null && msg.length() > 0) {
            		setToolStatusMessage(msg, true);
            	}
            }
        }
        else {
            println("No default labels found in selection.");
        }
    }

    private Symbol getDynamicSymbol( Symbol[] symbols ) {
        for (int i=0;i<symbols.length;i++) {
            if ( symbols[i].getSource() == SourceType.DEFAULT ) {
                return symbols[i];
            }
        }
        return null;
    }
}
