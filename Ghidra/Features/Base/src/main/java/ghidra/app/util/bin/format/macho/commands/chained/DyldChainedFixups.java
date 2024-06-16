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
package ghidra.app.util.bin.format.macho.commands.chained;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr;
import ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.DyldChainType;
import ghidra.app.util.bin.format.macho.dyld.DyldFixup;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DyldChainedFixups {

	/**
	 * Walks the chained fixup information and collects a {@link List} of {@link DyldFixup}s that 
	 * will need to be applied to the image
	 * 
	 * @param reader A {@link BinaryReader} that can read the image
	 * @param chainedImports chained imports (could be null)
	 * @param pointerFormat format of pointers within this chain
	 * @param page within data pages that has pointers to be unchained
	 * @param nextOff offset within the page that is the chain start
	 * @param auth_value_add value to be added to each chain pointer
	 * @param imagebase The image base
	 * @param symbolTable The {@link SymbolTable}, or null if not available
	 * @param log The log
	 * @param monitor A cancellable monitor
	 * @return A {@link List} of {@link DyldFixup}s
	 * @throws IOException If there was an IO-related issue
	 * @throws CancelledException If the user cancelled the operation
	 */
	public static List<DyldFixup> getChainedFixups(BinaryReader reader,
			DyldChainedImports chainedImports, DyldChainType pointerFormat, long page, long nextOff,
			long auth_value_add, long imagebase, SymbolTable symbolTable, MessageLog log,
			TaskMonitor monitor) throws IOException, CancelledException {
		List<DyldFixup> fixups = new ArrayList<>();

		long next = -1;
		while (next != 0) {
			monitor.checkCancelled();

			long chainLoc = page + nextOff;
			final long chainValue = DyldChainedPtr.getChainValue(reader, chainLoc, pointerFormat);
			long newChainValue = chainValue;
			boolean isAuthenticated = DyldChainedPtr.isAuthenticated(pointerFormat, chainValue);
			boolean isBound = DyldChainedPtr.isBound(pointerFormat, chainValue);
			Symbol symbol = null;
			Integer libOrdinal = null;

			if (isBound) {
				if (chainedImports == null) {
					log.appendMsg(
						"Error: dyld_chained_import array required to process bound chain fixup at " +
							chainLoc);
					return List.of();
				}
				if (symbolTable == null) {
					log.appendMsg(
						"Error: symbol table required to process bound chain fixup at " + chainLoc);
					return List.of();
				}
				int chainOrdinal = (int) DyldChainedPtr.getOrdinal(pointerFormat, chainValue);
				long addend = DyldChainedPtr.getAddend(pointerFormat, chainValue);
				DyldChainedImport chainedImport = chainedImports.getChainedImport(chainOrdinal);
				List<Symbol> globalSymbols = symbolTable.getGlobalSymbols(chainedImport.getName());
				if (globalSymbols.size() > 0) {
					symbol = globalSymbols.get(0);
					newChainValue = symbol.getAddress().getOffset();
					libOrdinal = chainedImport.getLibOrdinal();
				}
				newChainValue += isAuthenticated ? auth_value_add : addend;
			}
			else {
				if (isAuthenticated) {
					newChainValue = imagebase +
						DyldChainedPtr.getTarget(pointerFormat, chainValue) + auth_value_add;
				}
				else {
					newChainValue = DyldChainedPtr.getTarget(pointerFormat, chainValue);
					if (DyldChainedPtr.isRelative(pointerFormat)) {
						newChainValue += imagebase;
					}
				}
			}

			fixups.add(new DyldFixup(chainLoc, newChainValue, DyldChainedPtr.getSize(pointerFormat),
				symbol, libOrdinal));

			next = DyldChainedPtr.getNext(pointerFormat, chainValue);
			nextOff += next * DyldChainedPtr.getStride(pointerFormat);
		}
		return fixups;
	}

	/**
	 * Fixes up the program's chained pointers
	 * 
	 * @param fixups A {@link List} of the fixups
	 * @param program The {@link Program}
	 * @param imagebase The image base
	 * @param libraryPaths A {@link List} of library paths
	 * @param log The log
	 * @param monitor A cancellable monitor
	 * @return A {@link List} of fixed up {@link Address}'s
	 * @throws MemoryAccessException If there was a problem accessing memory
	 * @throws CancelledException If the user cancelled the operation
	 */
	public static List<Address> fixupChainedPointers(List<DyldFixup> fixups, Program program,
			Address imagebase, List<String> libraryPaths, MessageLog log, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		List<Address> fixedAddrs = new ArrayList<>();
		if (fixups.isEmpty()) {
			return fixedAddrs;
		}
		Memory memory = program.getMemory();
		for (DyldFixup fixup : fixups) {
			monitor.checkCancelled();
			Status status = Status.FAILURE;
			Address addr = imagebase.add(fixup.offset());
			try {
				if (fixup.size() == 8 || fixup.size() == 4) {
					if (fixup.size() == 8) {
						memory.setLong(addr, fixup.value());
					}
					else {
						memory.setInt(addr, (int) fixup.value());
					}
					fixedAddrs.add(addr);
					status = Status.APPLIED_OTHER;
				}
				else {
					status = Status.UNSUPPORTED;
				}
			}
			finally {
				program.getRelocationTable()
						.add(addr, status, 0, new long[] { fixup.value() }, fixup.size(),
							fixup.symbol() != null ? fixup.symbol().getName() : null);
			}
			if (fixup.symbol() != null && fixup.libOrdinal() != null) {
				fixupExternalLibrary(program, libraryPaths, fixup.libOrdinal(), fixup.symbol(), log,
					monitor);
			}
		}
		log.appendMsg("Fixed up " + fixedAddrs.size() + " chained pointers.");
		return fixedAddrs;
	}

	/**
	 * Associates the given {@link Symbol} with the correct external {@link Library} (fixing
	 * the <EXTERNAL> association)
	 * 
	 * @param program The {@link Program}
	 * @param libraryPaths A {@link List} of library paths
	 * @param libraryOrdinal The library ordinal
	 * @param symbol The {@link Symbol}
	 * @param log The log
	 * @param monitor A cancellable monitor
	 */
	private static void fixupExternalLibrary(Program program, List<String> libraryPaths,
			int libraryOrdinal, Symbol symbol, MessageLog log, TaskMonitor monitor) {
		ExternalManager extManager = program.getExternalManager();
		int libraryIndex = libraryOrdinal - 1;
		if (libraryIndex >= 0 && libraryIndex < libraryPaths.size()) {
			Library library = extManager.getExternalLibrary(libraryPaths.get(libraryIndex));
			ExternalLocation loc =
				extManager.getUniqueExternalLocation(Library.UNKNOWN, symbol.getName());
			if (loc != null) {
				try {
					loc.setName(library, symbol.getName(), SourceType.IMPORTED);
				}
				catch (InvalidInputException e) {
					log.appendException(e);
				}
			}
		}
	}

	//---------------------Below are used only by handled __thread_starts-------------------------

	/**
	 * Fixes up any chained pointers, starting at the given address.
	 * 
	 * @param reader A {@link BinaryReader} that can read the image
	 * @param chainStart The starting of address of the pointer chain to fix.
	 * @param nextOffSize The size of the next offset.
	 * @param imagebase The image base
	 * @param log The log
	 * @param monitor A cancellable monitor
	 * @return A list of addresses where pointer fixes were performed.
	 * @throws IOException If there was an IO-related issue
	 * @throws CancelledException If the user cancelled the operation
	 */
	public static List<DyldFixup> processPointerChain(BinaryReader reader, long chainStart,
			long nextOffSize, long imagebase, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		final long BIT63 = (0x1L << 63);
		final long BIT62 = (0x1L << 62);

		List<DyldFixup> fixups = new ArrayList<>();

		while (true) {
			monitor.checkCancelled();

			long chainValue = reader.readLong(chainStart);
			long fixedPointerValue = 0;

			// Bad chain value
			if ((chainValue & BIT62) != 0) {
				// this is a pointer, but is good now
			}

			// Pointer checked value
			if ((chainValue & BIT63) != 0) {
				//long tagType = (pointerValue >> 49L) & 0x3L;
				//long pacMod = ((pointerValue >> 32) & 0xffff);
				fixedPointerValue = imagebase + (chainValue & 0xffffffffL);
			}
			else {
				fixedPointerValue =
					((chainValue << 13) & 0xff000_0000_0000_000L) | (chainValue & 0x7ff_ffff_ffffL);
				if ((chainValue & 0x0400_0000_0000L) != 0) {
					fixedPointerValue |= 0x00ff_fc00_0000_0000L;
				}
			}

			fixups.add(new DyldFixup(chainStart, fixedPointerValue, 8, null, null));

			long nextValueOff = ((chainValue >> 51L) & 0x7ff) * nextOffSize;
			if (nextValueOff == 0) {
				break;
			}
			chainStart = chainStart + nextValueOff;
		}

		return fixups;
	}
}
