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
package ghidra.app.plugin.core.byteviewer;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.format.*;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * ByteBlockSet implementation for a Program object.
 */
class ProgramByteBlockSet implements ByteBlockSet {

	private MemoryBlock[] memBlocks;
	private Program program;
	private ByteBlockChangeManager bbcm;
	private ByteBlock[] blocks;
	private final ProgramByteViewerComponentProvider provider;

	ProgramByteBlockSet(ProgramByteViewerComponentProvider provider, Program program,
			ByteBlockChangeManager bbcm) {

		this.provider = provider;
		this.program = program;
		if (bbcm == null) {
			this.bbcm = new ByteBlockChangeManager(this);
		}
		else {
			this.bbcm = new ByteBlockChangeManager(this, bbcm);
		}

		getMemoryBlocks();
	}

	/**
	 * Get the blocks in this set.
	 */
	@Override
	public ByteBlock[] getBlocks() {
		return blocks;
	}

	/**
	 * Get the appropriate plugin event for the given block selection.
	 * @param source source to use in the event
	 * @param selection selection to use to generate the event
	 */
	@Override
	public ProgramSelectionPluginEvent getPluginEvent(String source, ByteBlockSelection selection) {

		AddressSet addrSet = new AddressSet();

		for (int i = 0; i < selection.getNumberOfRanges(); i++) {
			ByteBlockRange br = selection.getRange(i);
			ByteBlock block = br.getByteBlock();
			Address start = getAddress(block, br.getStartIndex());
			Address end = getAddress(block, br.getEndIndex());
			addrSet.add(new AddressRangeImpl(start, end));
		}
		return new ProgramSelectionPluginEvent(source, new ProgramSelection(addrSet), program);
	}

	/**
	 * Get a plugin event for the given block and offset.
	 * @param source source to use in the event
	 * @param block block to use to generate the event
	 * @param offset offset into the block
	 * @param column the column within the UI byte field
	 */
	@Override
	public ProgramLocationPluginEvent getPluginEvent(String source, ByteBlock block,
			BigInteger offset, int column) {

		ProgramLocation loc = provider.getLocation(block, offset, column);
		return new ProgramLocationPluginEvent(source, loc, program);
	}

	void processByteBlockChangeEvent(ByteBlockChangePluginEvent event) {
		if (event.getProgram() == program) {
			bbcm.add(event.getByteEditInfo());
		}
	}

	ByteBlockSelection getBlockSelection(ProgramSelection selection) {

		AddressRangeIterator iter = selection.getAddressRanges();
		List<ByteBlockRange> list = new ArrayList<ByteBlockRange>(3);

		while (iter.hasNext()) {
			AddressRange range = iter.next();

			for (int i = 0; i < blocks.length; i++) {
				Address blockStart = memBlocks[i].getStart();
				Address blockEnd = memBlocks[i].getEnd();
				AddressRange intersection =
					range.intersect(new AddressRangeImpl(blockStart, blockEnd));
				if (intersection != null) {
					ByteBlockInfo startInfo = getByteBlockInfo(intersection.getMinAddress());
					ByteBlockInfo endInfo = getByteBlockInfo(intersection.getMaxAddress());
					ByteBlockRange br = new ByteBlockRange(startInfo.getBlock(),
						startInfo.getOffset(), endInfo.getOffset());
					list.add(br);
				}
			}
		}
		ByteBlockRange[] bRange = new ByteBlockRange[list.size()];
		bRange = list.toArray(bRange);

		return new ByteBlockSelection(bRange);
	}

	/**
	 * Return true if the block has been changed at the given index.
	 * @param block  byte block
	 * @param index  offset into the block
	 * @param length number of bytes in question
	 */
	@Override
	public boolean isChanged(ByteBlock block, BigInteger index, int length) {
		return bbcm.isChanged(block, index, length);
	}

	void setByteBlockChangeManager(ByteBlockChangeManager byteBlockChangeManager) {
		bbcm = byteBlockChangeManager;
	}

	/**
	 * Send a notification that a byte block edit occurred.
	 * @param block block being edited
	 * @param index offset into the block
	 * @param oldValue old byte values
	 * @param newValue new byte values
	 */
	@Override
	public void notifyByteEditing(ByteBlock block, BigInteger index, byte[] oldValue,
			byte[] newValue) {

		ByteEditInfo edit =
			new ByteEditInfo(getAddress(block, BigInteger.ZERO), index, oldValue, newValue);

		bbcm.add(edit);
		provider.notifyEdit(edit);
	}

	///////////////////////////////////////////////////////////////////////
	SaveState getUndoRedoState() {
		return bbcm.getUndoRedoState();
	}

	void restoreUndoReoState(SaveState saveState) {
		bbcm.restoreUndoRedoState(saveState);
	}

	/**
	 * Get the byte block change manager
	 */
	ByteBlockChangeManager getByteBlockChangeManager() {
		return bbcm;
	}

	/**
	 * Get the address for the given block and offset.
	 */
	Address getAddress(ByteBlock block, BigInteger offset) {

		for (int i = 0; i < blocks.length; i++) {
			if (blocks[i] != block) {
				continue;
			}
			try {

				Address addr = memBlocks[i].getStart();
				return addr.addNoWrap(offset);

			}
			catch (AddressOverflowException e) {
				throw new IndexOutOfBoundsException("Offset " + offset + " is not in this block");
			}
		}
		return null;
	}

	/**
	 * Given an address, get the byte block info.
	 */
	ByteBlockInfo getByteBlockInfo(Address address) {

		if (!program.getMemory().contains(address)) {
			// this block set is out of date...eventually a new
			// ProgramByteBlockSetImpl will be created
			return null;
		}

		for (int i = 0; i < blocks.length; i++) {
			if (!memBlocks[i].contains(address)) {
				continue;
			}

			try {
				long off = address.subtract(memBlocks[i].getStart());
				BigInteger offset =
					(off < 0)
							? BigInteger.valueOf(off + 0x8000000000000000L).subtract(
								BigInteger.valueOf(0x8000000000000000L))
							: BigInteger.valueOf(off);
				return new ByteBlockInfo(blocks[i], offset);
			}
			catch (Exception e) {
				return null;
			}
		}
		return null;
	}

	Address getBlockStart(ByteBlock block) {
		return getAddress(block, BigInteger.ZERO);
	}

	Address getBlockStart(int blockNumber) {
		return memBlocks[blockNumber].getStart();
	}

	int getByteBlockNumber(Address blockStartAddr) {
		for (int i = 0; i < memBlocks.length; i++) {
			if (memBlocks[i].getStart().compareTo(blockStartAddr) == 0) {
				return i;
			}
		}
		return -1;
	}

	AddressSet getAddressSet(ByteBlockSelection selection) {

		AddressSet addrSet = new AddressSet();

		for (int i = 0; i < selection.getNumberOfRanges(); i++) {
			ByteBlockRange br = selection.getRange(i);
			ByteBlock block = br.getByteBlock();
			Address start = getAddress(block, br.getStartIndex());
			Address end = getAddress(block, br.getEndIndex());
			addrSet.add(new AddressRangeImpl(start, end));
		}
		return addrSet;
	}

	private void getMemoryBlocks() {
		Memory memory = program.getMemory();
		memBlocks = program.getMemory().getBlocks();
		blocks = new ByteBlock[memBlocks.length];
		for (int i = 0; i < memBlocks.length; i++) {
			blocks[i] = new MemoryByteBlock(program, memory, memBlocks[i]);
		}
	}

	@Override
	public void dispose() {
		// nothing to do?!?!?
	}

	public int startTransaction() {
		return program.startTransaction("Memory Edit");
	}

	public void endTransaction(int transactionID, boolean b) {
		program.endTransaction(transactionID, b);
	}
}
