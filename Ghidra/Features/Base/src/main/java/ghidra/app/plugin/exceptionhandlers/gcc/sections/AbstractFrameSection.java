/* ###
 * IP: GHIDRA
 * NOTE: This class was extracted from EhFrameSection.
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

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor;
import ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Extend this class to parse the call frame information exception handling structures within a 
 * particular frame memory section.
 */
abstract class AbstractFrameSection implements CieSource {

	/* Class Members */
	protected TaskMonitor monitor;
	protected Program program;

	private Map<Address, Cie> cieMap = new HashMap<>();

	/**
	 * Constructor for an individual frame section.
	 * 
	 * @param monitor a status monitor for indicating progress or allowing a task to be cancelled.
	 * @param program the program containing this particular frame section.
	 */
	AbstractFrameSection(TaskMonitor monitor, Program program) {
		this.monitor = monitor;
		this.program = program;
	}

	/**
	 * Creates data structures for the specified Common Information Entry (CIE) 
	 * and its Frame Description Entries (FDEs) as indicated by the regions.
	 * @param regions the region descriptors for the FDEs.
	 * @param cie the CIE for the FDEs.
	 */
	protected void createAugmentationData(List<RegionDescriptor> regions, Cie cie) {

		for (RegionDescriptor region : regions) {
			FrameDescriptionEntry frame = region.getFrameDescriptorEntry();
			Address augDataExAddr = frame.getAugmentationExDataAddress();
			if (augDataExAddr.equals(Address.NO_ADDRESS)) {
				continue;
			}
			Address addr = augDataExAddr;

			MemoryBlock block = program.getMemory().getBlock(augDataExAddr);

			int len = 0;
			int alignment = cie.getCodeAlignment();
			do {
				len += alignment;
				addr = addr.add(alignment);
			}
			while (program.getSymbolTable().getPrimarySymbol(addr) == null && block.contains(addr));

			if (len > 0) {
				CreateArrayCmd arrayCmd =
					new CreateArrayCmd(augDataExAddr, len, new ByteDataType(), 1);
				arrayCmd.applyTo(program);

			}
		}
	}

	/**
	 * Creates the data for a common information entry (CIE) at the address and puts a label and
	 * comment on it.
	 * @param curAddress the address with the CIE
	 * @param isInDebugFrame true indicates the frame containing this CIE is a debug frame.
	 * @return the <code>Cie</code> that was created
	 * @throws MemoryAccessException if memory for the CIE couldn't be read
	 * @throws ExceptionHandlerFrameException if a problem was encountered
	 */
	protected Cie createCie(Address curAddress, boolean isInDebugFrame)
			throws MemoryAccessException, ExceptionHandlerFrameException {

		Cie cie = new Cie(monitor, program, isInDebugFrame);
		cie.create(curAddress);
		if (cie.isEndOfFrame()) {
			return cie;
		}
		createCieLabel(curAddress);
		createCieComment(curAddress);
		return cie;
	}

	/**
	 * This class maintains a lookup of common information entry (CIE) objects; this 
	 * retrieves an existing object (by address), and creates a new CIE if not found.
	 * @param curAddress the address with the CIE
	 * @param isInDebugFrame true indicates the frame containing this CIE is a debug frame.
	 * @return the <code>Cie</code> that was either previously created, or a newly minted object.
	 * @throws MemoryAccessException if memory for the CIE couldn't be read
	 * @throws ExceptionHandlerFrameException if a problem was encountered
	 */
	protected Cie getCieOrCreateIfMissing(Address currAddress, boolean isInDebugFrame)
			throws MemoryAccessException, ExceptionHandlerFrameException {
		Cie cie = cieMap.get(currAddress);
		if (cie == null) {
			cie = createCie(currAddress, isInDebugFrame);
			cieMap.put(currAddress, cie);
		}
		return cie;
	}

	/**
	 * Creates a label indicating there is an CIE at the address.
	 * @param curAddress the address with the CIE
	 */
	protected void createCieLabel(Address curAddress) {
		try {
			String cieLabel = "cie_" + curAddress.toString();
			Symbol cieSym = program.getSymbolTable().getPrimarySymbol(curAddress);
			if (cieSym == null) {
				cieSym =
					program.getSymbolTable().createLabel(curAddress, cieLabel, SourceType.ANALYSIS);
			}
			else {
				cieSym.setName(cieLabel, SourceType.ANALYSIS);
			}
		}
		catch (InvalidInputException | DuplicateNameException e) {
			/* Output message and keep going even though couldn't create the label. */
			Msg.info(this, "Unable to label CIE -- " + e.getMessage(), e);
		}
	}

	/**
	 * Creates a comment indicating there is an CIE at the address.
	 * @param curAddress the address with the CIE
	 */
	protected void createCieComment(Address curAddress) {

		createPlateComment(curAddress, "Common Information Entry");
	}

	/**
	 * Creates a comment indicating there is an FDE at the address.
	 * @param curAddress the address with the FDE
	 */
	protected void createFdeComment(Address curAddress) {

		createPlateComment(curAddress, "Frame Descriptor Entry");
	}

	private void createPlateComment(Address curAddress, String fdeComment) {

		SetCommentCmd commentCmd =
			new SetCommentCmd(curAddress, CodeUnit.PLATE_COMMENT, fdeComment);
		commentCmd.applyTo(program);
	}
}
