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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Parses the exception handling structures within a '.debug_frame' memory section, which 
 * contains call frame debugging information.
 */
public class DebugFrameSection extends AbstractFrameSection {

	/* Class Constants */
	public static final String DEBUG_FRAME_BLOCK_NAME = ".debug_frame";

	/**
	 * Constructor for a debug frame section.
	 * 
	 * @param monitor a status monitor for indicating progress or allowing a task to be cancelled.
	 * @param program the program containing this debug frame section.
	 */
	public DebugFrameSection(TaskMonitor monitor, Program program) {
		super(monitor, program);
	}

	@Override
	public Cie getCie(Address currAddress)
			throws MemoryAccessException, ExceptionHandlerFrameException {
		return getCieOrCreateIfMissing(currAddress, true);
	}

	/**
	 * Analyzes and annotates the debug frame section.
	 * @return the region descriptors that compose the debug frame section.
	 * @throws MemoryAccessException if memory couldn't be read/written while processing the section.
	 * @throws AddressOutOfBoundsException if one or more expected addresses weren't in the program.
	 * @throws ExceptionHandlerFrameException if the FDE table can't be decoded.
	 */
	public List<RegionDescriptor> analyze() throws MemoryAccessException,
			AddressOutOfBoundsException, ExceptionHandlerFrameException, CancelledException {

		List<RegionDescriptor> descriptors = new ArrayList<>();

		MemoryBlock[] blocks = program.getMemory().getBlocks();

		int blockCount = blocks.length;
		monitor.setMaximum(blockCount);

		for (MemoryBlock block : blocks) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			if (block.getName().startsWith(DEBUG_FRAME_BLOCK_NAME)) {
				descriptors.addAll(analyzeSection(block));
			}
		}

		return Collections.unmodifiableList(descriptors);

	}

	private List<RegionDescriptor> analyzeSection(MemoryBlock curMemBlock)
			throws MemoryAccessException, AddressOutOfBoundsException, ExceptionHandlerFrameException {


		monitor.setMessage("Analyzing " + curMemBlock.getName() + " section");
		monitor.setShowProgressValue(true);
		monitor.setIndeterminate(true);

		ProgramLocation loc = new ProgramLocation(program, curMemBlock.getStart());
		Address curAddress = loc.getAddress();

		List<RegionDescriptor> regions = new ArrayList<>();


		while (curAddress != null && curAddress.compareTo(curMemBlock.getEnd()) < 0) {

			/* Get the Common Information Entry */
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
