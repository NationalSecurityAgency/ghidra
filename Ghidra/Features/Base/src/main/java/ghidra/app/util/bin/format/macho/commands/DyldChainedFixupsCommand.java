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

import static ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.chained.*;
import ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.DyldChainType;
import ghidra.app.util.bin.format.macho.dyld.DyldFixup;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a <code>dyld_chained_fixups_command</code> structure
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h">mach-o/fixup-chains.h</a> 
 */
public class DyldChainedFixupsCommand extends LinkEditDataCommand {

	private DyldChainedFixupHeader chainHeader;

	/**
	 * Creates and parses a new {@link DyldChainedFixupsCommand}
	 * 
	 * @param loadCommandReader A {@link BinaryReader reader} that points to the start of the load
	 *   command
	 * @param dataReader A {@link BinaryReader reader} that can read the data that the load command
	 *   references.  Note that this might be in a different underlying provider.
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	DyldChainedFixupsCommand(BinaryReader loadCommandReader, BinaryReader dataReader)
			throws IOException {
		super(loadCommandReader, dataReader);

		chainHeader = new DyldChainedFixupHeader(dataReader);
	}

	/**
	 * Gets the {@link DyldChainedFixupHeader}
	 * 
	 * @return The {@link DyldChainedFixupHeader}
	 */
	public DyldChainedFixupHeader getChainHeader() {
		return chainHeader;
	}

	@Override
	public String getCommandName() {
		return "dyld_chained_fixups_command";
	}

	@Override
	public void markup(Program program, MachHeader header, String source, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		Address addr = fileOffsetToAddress(program, header, dataoff, datasize);
		if (addr == null) {
			return;
		}
		super.markup(program, header, source, monitor, log);

		try {
			DataUtilities.createData(program, addr, chainHeader.toDataType(), -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			chainHeader.markup(program, addr, header, monitor, log);
		}
		catch (Exception e) {
			log.appendMsg(DyldChainedFixupsCommand.class.getSimpleName(),
				"Failed to markup: " + getContextualName(source, null));
		}
	}

	@Override
	public void markupRawBinary(MachHeader header, FlatProgramAPI api, Address baseAddress,
			ProgramModule parentModule, TaskMonitor monitor, MessageLog log) {
		try {
			super.markupRawBinary(header, api, baseAddress, parentModule, monitor, log);

			List<Address> addrs = api.getCurrentProgram()
					.getMemory()
					.locateAddressesForFileOffset(getLinkerDataOffset());
			if (addrs.size() <= 0) {
				throw new Exception("Chain Header does not exist in program");
			}
			Address dyldChainedHeader = addrs.get(0);

			DataType cHeader = chainHeader.toDataType();
			api.createData(dyldChainedHeader, cHeader);

			Address segsAddr = dyldChainedHeader.add(chainHeader.getStartsOffset());

			DyldChainedStartsInImage chainedStartsInImage = chainHeader.getChainedStartsInImage();
			int[] segInfoOffset = chainedStartsInImage.getSegInfoOffset();

			List<DyldChainedStartsInSegment> chainedStarts =
				chainedStartsInImage.getChainedStarts();
			for (int i = 0; i < chainedStarts.size(); i++) {
				DyldChainedStartsInSegment startsInSeg = chainedStarts.get(i);
				DataType dataType = startsInSeg.toDataType();

				api.createData(segsAddr.add(segInfoOffset[i]), dataType);
			}
		}
		catch (Exception e) {
			log.appendMsg("Unable to create " + getCommandName());
			log.appendException(e);
		}
	}

	/**
	 * Walks this command's chained fixup information and collects a {@link List} of 
	 * {@link DyldFixup}s that will need to be applied to the image
	 * 
	 * @param reader A {@link BinaryReader} that can read the image
	 * @param imagebase The image base
	 * @param symbolTable The {@link SymbolTable}, or null if not available
	 * @param log The log
	 * @param monitor A cancellable monitor
	 * @return A {@link List} of {@link DyldFixup}s
	 * @throws IOException If there was an IO-related issue
	 * @throws CancelledException If the user cancelled the operation
	 */
	public List<DyldFixup> getChainedFixups(BinaryReader reader, long imagebase,
			SymbolTable symbolTable, MessageLog log, TaskMonitor monitor)
			throws IOException, CancelledException {
		List<DyldFixup> result = new ArrayList<>();
		Map<DyldChainType, Integer> countMap = new HashMap<>();
		for (DyldChainedStartsInSegment chainStart : chainHeader.getChainedStartsInImage()
				.getChainedStarts()) {
			if (chainStart == null) {
				continue;
			}

			DyldChainType ptrFormat = DyldChainType.lookupChainPtr(chainStart.getPointerFormat());
			monitor.initialize(chainStart.getPageCount(),
				"Getting " + ptrFormat.getName() + " chained pointer fixups...");

			try {
				for (int index = 0; index < chainStart.getPageCount(); index++) {
					monitor.increment();
	
					long page = chainStart.getSegmentOffset() + (chainStart.getPageSize() * index);
					int pageEntry = chainStart.getPageStarts()[index] & 0xffff;
					if (pageEntry == DYLD_CHAINED_PTR_START_NONE) {
						continue;
					}
					List<DyldFixup> fixups =
						DyldChainedFixups.getChainedFixups(reader, chainHeader.getChainedImports(),
							ptrFormat, page, pageEntry, 0, imagebase, symbolTable, log, monitor);
					result.addAll(fixups);
					countMap.put(ptrFormat, countMap.getOrDefault(ptrFormat, 0) + fixups.size());
				}
			}	
			catch(IOException e) {
				log.appendMsg("Failed to get segment chain fixups at 0x%x"
						.formatted(chainStart.getSegmentOffset()));
			}
		}
		countMap.forEach((type, count) -> log
				.appendMsg("Discovered " + count + " " + type + " chained pointers."));
		return result;
	}
}
