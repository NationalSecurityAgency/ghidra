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
package ghidra.app.plugin.exceptionhandlers.gcc.sections;

import java.util.*;

import ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor;
import ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 * Parses the call frame information exception handling structures within an '.eh_frame' 
 * memory section.
 */
public class EhFrameSection extends AbstractFrameSection {

	/* Class Constants */
	public static final String EH_FRAME_BLOCK_NAME = ".eh_frame";

	/**
	 * Constructor for an eh frame section.
	 * 
	 * @param monitor a status monitor for indicating progress or allowing a task to be cancelled.
	 * @param program the program containing this eh frame section.
	 */
	public EhFrameSection(TaskMonitor monitor, Program program) {
		super(monitor, program);
	}

	@Override
	public Cie getCie(Address currAddress)
			throws MemoryAccessException, ExceptionHandlerFrameException {
		return getCieOrCreateIfMissing(currAddress, false);
	}

	/**
	 * Analyzes and annotates the eh frame section.
	 * 
	 * @param fdeTableCount the number of exception handler FDEs.
	 * @return the region descriptors for the eh frame section.
	 * @throws MemoryAccessException if memory couldn't be read/written while processing the eh frame.
	 * @throws AddressOutOfBoundsException if one or more expected addresses weren't in the program.
	 * @throws ExceptionHandlerFrameException if a problem was encountered determining eh frame data.
	 */
	public List<RegionDescriptor> analyze(int fdeTableCount)
			throws MemoryAccessException, AddressOutOfBoundsException, ExceptionHandlerFrameException {

		MemoryBlock memBlock = program.getMemory().getBlock(EH_FRAME_BLOCK_NAME);

		if (memBlock != null && !monitor.isCancelled()) {
			return Collections.unmodifiableList(analyzeSection(memBlock));
		}

		return new ArrayList<RegionDescriptor>();
	}

	private List<RegionDescriptor> analyzeSection(MemoryBlock curMemBlock)
			throws MemoryAccessException, AddressOutOfBoundsException, ExceptionHandlerFrameException {

		monitor.setMessage("Analyzing " + curMemBlock.getName() + " section");
		monitor.setShowProgressValue(true);
		monitor.setIndeterminate(false);
		long bytesInBlock = curMemBlock.getSize();
		monitor.initialize(bytesInBlock);

		Address startAddr = curMemBlock.getStart();
		ProgramLocation loc = new ProgramLocation(program, startAddr);
		Address curAddress = loc.getAddress();

		List<RegionDescriptor> regions = new ArrayList<>();


		while (curAddress != null && curAddress.compareTo(curMemBlock.getEnd()) < 0) {

			monitor.setProgress(curAddress.subtract(startAddr));

			/* Get the Common Information Entry (CIE) */
			Cie cie = getCie(curAddress);

			/* Check for the end of the frame record. */
			if (cie.isEndOfFrame()) {
				break;
			}

			curAddress = cie.getNextAddress();

			/* 
			 * Add each Frame Description Entry (FDE) for the current CIE.
			 */
			while (curAddress != null && (curAddress.compareTo(curMemBlock.getEnd()) < 0)) {

				monitor.setProgress(curAddress.subtract(startAddr));

				Address currFdeAddr = curAddress;

				try {

					FrameDescriptionEntry fde = new FrameDescriptionEntry(monitor, program, this);
					RegionDescriptor region = fde.create(curAddress);

					if (fde.isEndOfFrame()) {
						break;
					}

					if (region != null) {
						regions.add(region);
						createFdeComment(curAddress);
						monitor.incrementProgress(1);
					}

					curAddress = fde.getNextAddress(); // This can be null.

				} catch (ExceptionHandlerFrameException efe) {
					// May have run into another CIE.
					curAddress = currFdeAddr;
					break;
				}
			}

			createAugmentationData(regions, cie);
		}
		return regions;
	}
}
