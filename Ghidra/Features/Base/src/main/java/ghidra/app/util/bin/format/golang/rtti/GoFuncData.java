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
package ghidra.app.util.bin.format.golang.rtti;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.golang.structmapping.*;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.InvalidInputException;

@StructureMapping(structureName = "runtime._func")
public class GoFuncData implements StructureMarkup<GoFuncData> {
	@ContextField
	private GoRttiMapper programContext;

	@ContextField
	private StructureContext<GoFuncData> context;

	@FieldMapping
	@EOLComment("description")
	@MarkupReference("funcAddress")
	private long entryoff;

	@FieldMapping
	@MarkupReference("nameAddress")
	private long nameoff;

	public Address getFuncAddress() {
		return getModuledata().getText().add(entryoff);
	}

	public Address getNameAddress() {
		return getModuledata().getFuncnametab().getArrayAddress().add(nameoff);
	}

	public String getName() throws IOException {
		BinaryReader reader =
			programContext.getReader(getModuledata().getFuncnametab().getArrayOffset() + nameoff);
		return reader.readNextUtf8String();
	}

	public String getDescription() throws IOException {
		return getName() + "@" + getFuncAddress();
	}

	public boolean isInline() {
		return entryoff == -1 || entryoff == NumericUtilities.MAX_UNSIGNED_INT32_AS_LONG;
	}

	private GoModuledata getModuledata() {
		return programContext.findContainingModuleByFuncData(context.getStructureStart());
	}

	@Override
	public StructureContext<GoFuncData> getStructureContext() {
		return context;
	}

	@Override
	public String getStructureName() throws IOException {
		return getName();
	}

	@Override
	public void additionalMarkup() throws IOException {
		Address addr = getFuncAddress();
		String name = SymbolUtilities.replaceInvalidChars(getName(), true);
		Program program = programContext.getProgram();

		Function function = program.getListing().getFunctionAt(addr);
		if (function == null) {
			try {
				if (!program.getMemory()
						.getLoadedAndInitializedAddressSet()
						.contains(addr)) {
					Msg.warn(this,
						"Unable to create function not contained within loaded memory: %s@%s"
								.formatted(name, addr));
					return;
				}
				function = program.getFunctionManager()
						.createFunction(name, addr, new AddressSet(addr), SourceType.IMPORTED);
			}
			catch (OverlappingFunctionException | InvalidInputException e) {
				Msg.error(this, e);
			}
		}
		else {
			// TODO: this does nothing.  re-evalulate this logic
			programContext.labelAddress(addr, name);
		}
	}

}
/*
struct runtime._func  
Length: 40  Alignment: 4
{ 
  uint32                    entryoff         
  int32                      nameoff         
  int32                      args              
  uint32                    deferreturn   
  uint32                    pcsp              
  uint32                    pcfile             
  uint32                    pcln               
  uint32                    npcdata        
  uint32                    cuOffset        
  runtime.funcID      funcID            
  runtime.funcFlag  flag                
  uint8[1]                _                    
  uint8                      nfuncdata     
} pack()

*/
