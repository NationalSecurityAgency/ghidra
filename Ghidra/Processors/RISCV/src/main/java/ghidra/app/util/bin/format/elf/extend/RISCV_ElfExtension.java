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
package ghidra.app.util.bin.format.elf.extend;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ContextChangeException;

public class RISCV_ElfExtension extends ElfExtension {

	//TODO  not sure about these
    public static final String RISCV_PROC="RISCV";
    public static final String RISCV_SUFFIX="_RISCV";
    
    @Override
    public boolean canHandle(ElfHeader elf) {
    	return elf.e_machine() == ElfConstants.EM_RISCV;
    }

    @Override
    public boolean canHandle(ElfLoadHelper elfLoadHelper) {
    	if (!canHandle(elfLoadHelper.getElfHeader()))
    		return false;
	
    	Language language = elfLoadHelper.getProgram().getLanguage();
    	int size =language.getLanguageDescription().getSize();
    	return ((32 == size || 64 == size) && language.getProcessor().toString().equals(RISCV_PROC));
    }

    @Override
    public String getDataTypeSuffix() {
    	return RISCV_SUFFIX;
    }
}
