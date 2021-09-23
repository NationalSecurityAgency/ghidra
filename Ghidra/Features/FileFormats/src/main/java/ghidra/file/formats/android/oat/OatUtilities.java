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
package ghidra.file.formats.android.oat;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.file.formats.android.dex.format.ClassDataItem;
import ghidra.file.formats.android.dex.format.EncodedMethod;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

final class OatUtilities {

	/**
	 * Returns a BinaryReader based at the "oatdata" symbol.
	 * The ".rodata" section contains the OAT information.
	 * Returns null when the "oatdata" symbol does not exist.
	 */
	final static BinaryReader getBinaryReader(Program program) {
		if (OatConstants.isOAT(program)) {
			Symbol symbol = getOatDataSymbol(program);
			if (symbol != null && symbol.getName().equals(OatConstants.SYMBOL_OAT_DATA)) {
				ByteProvider provider =
					new MemoryByteProvider(program.getMemory(), symbol.getAddress());
				return new BinaryReader(provider, !program.getLanguage().isBigEndian());
			}
		}
		return null;
	}

	final static boolean isELF(Program program) {
		return ElfLoader.ELF_NAME.equals(program.getExecutableFormat());
	}

	final static Symbol getOatDataSymbol(Program program) {
		if (isELF(program)) {
			MemoryBlock block = program.getMemory().getBlock(ElfSectionHeaderConstants.dot_rodata);
			if (block != null) {
				SymbolTable symbolTable = program.getSymbolTable();
				Symbol oatDataSymbol = symbolTable.getPrimarySymbol(block.getStart());
				if (oatDataSymbol != null &&
					oatDataSymbol.getName().equals(OatConstants.SYMBOL_OAT_DATA)) {
					return oatDataSymbol;
				}
			}
		}
		return null;
	}

	final static Symbol getOatExecSymbol(Program program) {
		if (isELF(program)) {
			MemoryBlock block = program.getMemory().getBlock(ElfSectionHeaderConstants.dot_text);
			if (block != null) {
				SymbolTable symbolTable = program.getSymbolTable();
				Symbol oatExecSymbol = symbolTable.getPrimarySymbol(block.getStart());
				if (oatExecSymbol != null &&
					oatExecSymbol.getName().equals(OatConstants.SYMBOL_OAT_EXEC)) {
					return oatExecSymbol;
				}
			}
		}
		return null;
	}

	final static Symbol getOatLastWordSymbol(Program program) {
		if (isELF(program)) {
			MemoryBlock block = program.getMemory().getBlock(ElfSectionHeaderConstants.dot_text);
			if (block != null) {
				SymbolTable symbolTable = program.getSymbolTable();
				List<Symbol> oatLastWordSymbols =
					symbolTable.getGlobalSymbols(OatConstants.SYMBOL_OAT_LASTWORD);
				if (oatLastWordSymbols.size() == 1) {
					return oatLastWordSymbols.get(0);
				}
			}
		}
		return null;
	}

//	final static Symbol getSymbol( Program program, String name ) {
//		SymbolTable symbolTable = program.getSymbolTable( );
//		List< Symbol > symbols = symbolTable.getSymbols( name, program.getGlobalNamespace( ) );
//		if ( symbols.size( ) != 1 ) {
//			return null;//TODO
//		}
//		return symbols.get( 0 );
//	}

	final static List<EncodedMethod> getAllMethods(ClassDataItem classDataItem) {
		List<EncodedMethod> list = new ArrayList<EncodedMethod>();
		list.addAll(classDataItem.getDirectMethods());
		list.addAll(classDataItem.getVirtualMethods());
		return list;
	}

	final static Address adjustForThumbAsNeeded(OatHeader oatHeader, Program program,
			Address address, MessageLog log) {
		long displacement = address.getOffset();
		if (oatHeader.getInstructionSet() == OatInstructionSet.kThumb2) {
			if ((displacement & 0x1) == 0x1) {//thumb code?
				address = address.subtract(1);

				Register register = program.getLanguage().getRegister("TMode");
				RegisterValue value = new RegisterValue(register, BigInteger.valueOf(1));
				try {
					program.getProgramContext().setRegisterValue(address, address, value);
				}
				catch (ContextChangeException e) {
					log.appendException(e);
				}
			}
		}
		return address;
	}
}
