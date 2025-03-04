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
package ghidra.app.util.opinion;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class MachoProgramUtils {

	/**
	 * Gets the next available {@link Address} in the {@link Program}
	 * 
	 * @param program The {@link Program}
	 * @return The next available {@link Address} in the {@link Program}
	 */
	public static Address getNextAvailableAddress(Program program) {
		Address maxAddress = null;
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.isOverlay()) {
				continue;
			}
			if (maxAddress == null || block.getEnd().compareTo(maxAddress) > 0) {
				maxAddress = block.getEnd();
			}
		}
		if (maxAddress == null) {
			return program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
		}
		long maxAddr = maxAddress.getOffset();
		long remainder = maxAddr % 0x1000;
		return maxAddress.getNewAddress(maxAddr + 0x1000 - remainder);
	}

	/**
	 * Adds the {@link MemoryBlock#EXTERNAL_BLOCK_NAME EXERNAL block} to memory, or adds to an
	 * existing one
	 * 
	 * @param program The {@link Program}
	 * @param size The desired size of the new EXTERNAL block
	 * @param log The {@link MessageLog}
	 * @return The {@link Address} of the new (or new piece) of EXTERNAL block
	 * @throws Exception if there was an issue creating or adding to the EXTERNAL block
	 */
	public static Address addExternalBlock(Program program, long size, MessageLog log)
			throws Exception {
		Memory mem = program.getMemory();
		MemoryBlock externalBlock = mem.getBlock(MemoryBlock.EXTERNAL_BLOCK_NAME);
		Address ret;
		if (externalBlock != null) {
			ret = externalBlock.getEnd().add(1);
			MemoryBlock newBlock = mem.createBlock(externalBlock, "REEXPORTS", ret, size);
			mem.join(externalBlock, newBlock);
			//joinedBlock.setName(MemoryBlock.EXTERNAL_BLOCK_NAME);
		}
		else {
			ret = MachoProgramUtils.getNextAvailableAddress(program);
			externalBlock =
				mem.createUninitializedBlock(MemoryBlock.EXTERNAL_BLOCK_NAME, ret, size, false);
			externalBlock.setWrite(true);
			externalBlock.setArtificial(true);
			externalBlock.setComment(
				"NOTE: This block is artificial and is used to make relocations work correctly");
		}
		return ret;
	}
}
