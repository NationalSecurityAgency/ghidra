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
package ghidra.app.util.bin.format.macho.relocation;

import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.NList;
import ghidra.app.util.bin.format.macho.commands.SymbolTableCommand;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.NotFoundException;

/**
 * A representation of a single Mach-O relocation that the {@link MachoRelocationHandler} will use
 * to perform the relocation.  In Mach-O, some relocations may be "paired," so an instance of this
 * class may contain 2 {@link RelocationInfo}s. 
 */
public class MachoRelocation {

	private Program program;
	private AddressSpace space;
	private MachHeader machoHeader;

	private Address relocationAddress;
	private RelocationInfo relocationInfo;
	private Symbol targetSymbol;
	private Section targetSection;
	private Address targetPointer;

	private RelocationInfo relocationInfoExtra;
	private Symbol targetSymbolExtra;
	private Section targetSectionExtra;
	private Address targetPointerExtra;

	/**
	 * Creates a new unpaired {@link MachoRelocation} object
	 * 
	 * @param program The program
	 * @param machoHeader The Mach-O header
	 * @param relocationAddress The {@link Address} the relocation takes place at
	 * @param relocationInfo The lower-level {@link RelocationInfo} that describes the relocation
	 */
	public MachoRelocation(Program program, MachHeader machoHeader, Address relocationAddress,
			RelocationInfo relocationInfo) {
		this.program = program;
		this.space = program.getAddressFactory().getDefaultAddressSpace();
		this.machoHeader = machoHeader;
		this.relocationAddress = relocationAddress;
		this.relocationInfo = relocationInfo;
		if (relocationInfo.isScattered()) {
			this.targetPointer = space.getAddress(relocationInfo.getValue());
		}
		else if (relocationInfo.isExternal()) {
			this.targetSymbol = findTargetSymbol(relocationInfo);
		}
		else {
			this.targetSection = findTargetSection(relocationInfo);
		}
	}

	/**
	 * Creates a new paired {@link MachoRelocation} object
	 * 
	 * @param program The program
	 * @param machoHeader The Mach-O header
	 * @param relocationAddress The {@link Address} the relocation takes place at
	 * @param relocationInfo The lower-level {@link RelocationInfo} that describes the first part
	 *   of the relocation
	 * @param relocationInfoExtra The lower-level {@link RelocationInfo} that describes the second
	 *   part of the relocation
	 */
	public MachoRelocation(Program program, MachHeader machoHeader, Address relocationAddress,
			RelocationInfo relocationInfo, RelocationInfo relocationInfoExtra) {
		this(program, machoHeader, relocationAddress, relocationInfo);
		this.relocationInfoExtra = relocationInfoExtra;
		if (relocationInfoExtra.isScattered()) {
			this.targetPointerExtra = space.getAddress(relocationInfoExtra.getValue());
		}
		else if (relocationInfoExtra.isExternal()) {
			this.targetSymbolExtra = findTargetSymbol(relocationInfoExtra);
		}
		else {
			this.targetSectionExtra = findTargetSection(relocationInfoExtra);
		}
	}

	/**
	 * Gets the {@link Program} associated with this relocation
	 * 
	 * 
	 * @return The {@link Program} associated with this relocation
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Gets the {@link Address} the relocation takes place at
	 * 
	 * @return The {@link Address} the relocation takes place at
	 */
	public Address getRelocationAddress() {
		return relocationAddress;
	}

	/**
	 * Gets the lower-level {@link RelocationInfo} that describes the relocation
	 * 
	 * @return The lower-level {@link RelocationInfo} that describes the relocation
	 */
	public RelocationInfo getRelocationInfo() {
		return relocationInfo;
	}

	/**
	 * Gets the lower-level {@link RelocationInfo} that describes the second part of the paired 
	 * relocation.  This could be null if the relocation is not paired.
	 * 
	 * @return The lower-level {@link RelocationInfo} that describes the second part of the paired 
	 *   relocation, or null if the relocation is not paired
	 */
	public RelocationInfo getRelocationInfoExtra() {
		return relocationInfoExtra;
	}
	
	/**
	 * Gets the {@link Address} of the relocation target
	 * 
	 * @return The {@link Address} of the relocation target
	 * @throws NotFoundException If the {@link Address} of the relocation target could not be found
	 */
	public Address getTargetAddress() throws NotFoundException {
		if (targetSymbol != null) {
			return targetSymbol.getAddress();
		}
		if (targetSection != null) {
			return space.getAddress(targetSection.getAddress());
		}
		if (targetPointer != null) {
			return targetPointer;
		}
		throw new NotFoundException("Relocation target not found");
	}
	
	/**
	 * Gets the {@link Address} of the extra relocation target
	 * 
	 * @return The {@link Address} of the extra relocation target
	 * @throws NotFoundException If the {@link Address} of the extra relocation target could not be 
	 *   found (of if there wasn't an extra relocation target).
	 */
	public Address getTargetAddressExtra() throws NotFoundException {
		if (targetSymbolExtra != null) {
			return targetSymbolExtra.getAddress();
		}
		if (targetSectionExtra != null) {
			return space.getAddress(targetSectionExtra.getAddress());
		}
		if (targetPointerExtra != null) {
			return targetPointerExtra;
		}
		throw new NotFoundException("Extra relocation target not found");
	}
	
	/**
	 * Checks to see if this relocation requires work to be done on it. Since our
	 * {@link MachoLoader loader} does not allow non-default image bases, it is unnecessary to 
	 * perform relocations under certain conditions.  
	 * 
	 * @return True if relocation steps are needed; otherwise, false
	 */
	public boolean requiresRelocation() {
		boolean requires = relocationInfo.isExternal() && !relocationInfo.isScattered();
		if (relocationInfoExtra != null) {
			requires = requires ||
				(relocationInfoExtra.isExternal() && !relocationInfoExtra.isScattered());
		}
		return requires;
	}

	/**
	 * Gets a short description of the target of the relocation
	 * 
	 * @return A short description of the target of the relocation
	 */
	public String getTargetDescription() {
		StringBuilder sb = new StringBuilder();

		if (targetPointer != null) {
			sb.append(targetPointer);
		}
		else if (targetSymbol != null) {
			sb.append(targetSymbol.getName());
		}
		else if (targetSection != null) {
			sb.append(targetSection.getSectionName());
		}
		else {
			sb.append(NumericUtilities.toHexString(relocationInfo.getValue()));
		}

		if (relocationInfoExtra != null) {
			sb.append(" / ");
			if (targetPointerExtra != null) {
				sb.append(targetPointerExtra);
			}
			else if (targetSymbolExtra != null) {
				sb.append(targetSymbolExtra.getName());
			}
			else if (targetSectionExtra != null) {
				sb.append(targetSectionExtra.getSectionName());
			}
			else {
				sb.append(NumericUtilities.toHexString(relocationInfoExtra.getValue()));
			}
		}
		return sb.toString();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(String.format("Symbol: %s, Section: %s\n", targetSymbol, targetSection));
		sb.append(relocationInfo + "\n");

		if (relocationInfoExtra != null) {
			sb.append(
				String.format("Symbol: %s, Section: %s\n", targetSymbolExtra, targetSectionExtra));
			sb.append(relocationInfoExtra);
		}
		return sb.toString();
	}

	/**
	 * Attempts to find the target {@link Symbol} associated with the given lower-level 
	 * {@link RelocationInfo}.  This method is only useful when the given {@link RelocationInfo} is 
	 * marked as "external".
	 * 
	 * @param relocInfo The lower-level {@link RelocationInfo} that describes the relocation
	 * @return The relocation's target {@link Symbol}, or null if one was not found
	 */
	private Symbol findTargetSymbol(RelocationInfo relocInfo) {
		Symbol sym = null;
		NList nlist = machoHeader.getFirstLoadCommand(SymbolTableCommand.class)
				.getSymbolAt(relocInfo.getValue());
		Address addr = space.getAddress(nlist.getValue());
		sym = program.getSymbolTable()
				.getSymbol(SymbolUtilities.replaceInvalidChars(nlist.getString(), true), addr,
					null);
		if (sym == null) {
			sym = SymbolUtilities.getLabelOrFunctionSymbol(program, nlist.getString(), err -> {
				// no logging
			});
		}
		return sym;
	}

	/**
	 * Attempts to find the target {@link Section} associated with the given lower-level 
	 * {@link RelocationInfo}.  This method is only useful when the given {@link RelocationInfo} is 
	 * NOT marked as "external".
	 * 
	 * @param relocInfo The lower-level {@link RelocationInfo} that describes the relocation
	 * @return The relocation's target {@link Section}, or null if one was not found
	 */
	private Section findTargetSection(RelocationInfo relocInfo) {
		int index = relocInfo.getValue() - 1;
		if (index >= 0 && index < machoHeader.getAllSections().size()) {
			return machoHeader.getAllSections().get(index);
		}
		return null;
	}
}
