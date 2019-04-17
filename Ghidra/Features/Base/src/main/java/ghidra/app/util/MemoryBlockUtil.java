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
package ghidra.app.util;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressLabelInfo;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * A utility class that encapsulates the creation
 * of different types of memory blocks in a program.
 */
public class MemoryBlockUtil {

	private final static byte MEMORY_CONFLICT_UNKNOWN = 0;
	private final static byte MEMORY_CONFLICT_IGNORE = 1;
	private final static byte MEMORY_CONFLICT_REMOVE_WHOLE = 2;
	private final static byte MEMORY_CONFLICT_REMOVE_1ST_HALF = 3;
	private final static byte MEMORY_CONFLICT_REMOVE_2ND_HALF = 4;
	private final static byte MEMORY_CONFLICT_REMOVE_MIDDLE = 5;

	private Listing listing;
	private Memory memory;
	private SymbolTable symbolTable;
	private MemoryConflictHandler handler;
	private StringBuffer messages;

	/**
	 * Constructs a new memory block utility.
	 * @param program  the program having memory blocks created
	 * @param handler  the memory conflict handler
	 */
	public MemoryBlockUtil(Program program, MemoryConflictHandler handler) {
		this.listing = program.getListing();
		this.memory = program.getMemory();
		this.symbolTable = program.getSymbolTable();
		this.handler = handler;
		this.messages = new StringBuffer();
	}

	/**
	 * Return error messages.
	 */
	public String getMessages() {
		return messages.toString();
	}

	/**
	 * This method performs cleanup with this object is no
	 * longer needed. This method should be invoked
	 * to prevent potential memory leaks.
	 */
	public void dispose() {
		listing = null;
		memory = null;
		handler = null;
	}

	/**
	 * Creates a bit or byte mapped memory block.
	 *
	 * @param isBitMapped if true, creates a bit mapped block, otherwise a byte mapped block
	 * @param name    name of the block
	 * @param start   start address of the block
	 * @param base    base address for the bit block
	 * @param length  length of the block
	 * @param comment comment for the block
	 * @param source  source of the block, where it originated
	 * @param r       is block read-only?
	 * @param w       is block writeable?
	 * @param x       is block executable?
	 * @return the newly created memory block or null (see messages)
	 */
	public MemoryBlock createMappedBlock(boolean isBitMapped, String name, Address start,
			Address base, int length, String comment, String source, boolean r, boolean w,
			boolean x) {
		try {

			MemoryBlock block = isBitMapped ? memory.createBitMappedBlock(name, start, base, length)
					: memory.createByteMappedBlock(name, start, base, length);

			block.setComment(comment);
			block.setSourceName(source);
			block.setRead(r);
			block.setWrite(w);
			block.setExecute(x);

			renameFragment(start, name);

			return block;
		}
		catch (LockException e) {
			appendMessage("Failed to create '" + name +
				"' mapped memory block: exclusive lock/checkout required");
		}
		catch (MemoryConflictException e) {
			appendMessage("Failed to create '" + name + "' mapped memory block: " + e.getMessage());
		}
		catch (AddressOverflowException e) {
			appendMessage("Failed to create '" + name + "' mapped memory block: " + e.getMessage());
		}
		return null;
	}

	/**
	 * Creates an uninitialized memory block.
	 * @param isOverlay true if overlay space and block should be createds
	 * @param name    name of the block
	 * @param start   start address of the block
	 * @param length  length of the block
	 * @param comment comment for the block
	 * @param source  source of the block, where it originated
	 * @param r       is block read-only?
	 * @param w       is block writeable?
	 * @param x       is block executable?
	 *
	 * @return the newly created memory block or null (see messages)
	 */
	public MemoryBlock createUninitializedBlock(boolean isOverlay, String name, Address start,
			long length, String comment, String source, boolean r, boolean w, boolean x) {

		try {
			MemoryBlock block = memory.createUninitializedBlock(name, start, length, isOverlay);
			setBlockAttributes(block, comment, source, r, w, x);
			renameFragment(start, name);
			return block;
		}
		catch (LockException e) {
			appendMessage(
				"Failed to create '" + name + "' memory block: exclusive lock/checkout required");
		}
		catch (DuplicateNameException e) {
			appendMessage("Failed to create '" + name + "' memory block: " + e.getMessage());
		}
		catch (MemoryConflictException e) {
			appendMessage("Failed to create '" + name + "' memory block: " + e.getMessage());
		}
		catch (AddressOverflowException e) {
			appendMessage("Failed to create '" + name + "' memory block: " + e.getMessage());
		}
		return null;
	}

	/**
	 * Creates an initialized memory block using a byte array.
	 *
	 * @param name    name of the block
	 * @param start   start address of the block
	 * @param data    the bytes for the memory block
	 * @param comment comment for the block
	 * @param source  source of the block, where it originated
	 * @param r       is block read-only?
	 * @param w       is block writeable?
	 * @param x       is block executable?
	 * @param monitor the task monitor
	 * @return the newly created memory block or null (see messages)
	 */
	public MemoryBlock createInitializedBlock(String name, Address start, byte[] data,
			String comment, String source, boolean r, boolean w, boolean x, TaskMonitor monitor)
			throws AddressOverflowException {

		return createInitializedBlock(name, start, new ByteArrayInputStream(data), data.length,
			comment, source, r, w, x, monitor);
	}

	/**
	 * Creates an initialized memory block using the specified input stream.  If the length
	 * of the block is greater than the maximum size of a memory block (0x40000000), then
	 * the block is broken in to multiple blocks.  The first block created will have the
	 * given name and each subsequent block will have ".1", ".2", etc., appended to the base
	 * name. The first block created will be the one returned by this call.
	 * <p>
	 * The MemoryConflictHandler is responsible for determining
	 * how to deal with memory conflict exceptions that occur with
	 * initialized memory blocks.
	 * <p>
	 * Any uninitialized memory blocks involved in the conflict
	 * will be removed and replaced with initialized memory blocks.
	 * <p>
	 * If only a portion of the uninitialized memory block has caused a
	 * conflict, then only that portion will be removed and replaced.
	 * Subsequently, the uninitialized memory blocks boundaries may change.
	 * <p>
	 * When other types of memory blocks are involved in a conflict,
	 * only the bytes will be replaced. The boundaries will not change.
	 * Initialized memory blocks will be created around the existing ones.
	 * Also, when bytes change from under an existing memory block, then
	 * all code units in the range of the conflict will be cleared.
	 *
	 * @param name       name of the block
	 * @param start      start address of the block
	 * @param dataInput  an input stream containing the bytes for the block
	 * @param dataLength length of the block
	 * @param comment comment for the block
	 * @param source  source of the block, where it originated
	 * @param r       is block read-only?
	 * @param w       is block writeable?
	 * @param x       is block executable?
	 * @param monitor the task monitor
	 * @return new block or null on failure (see messages)
	 */
	public MemoryBlock createInitializedBlock(String name, Address start, InputStream dataInput,
			long dataLength, String comment, String source, boolean r, boolean w, boolean x,
			TaskMonitor monitor) throws AddressOverflowException {

		if (!memory.getProgram().hasExclusiveAccess()) {
			appendMessage(
				"Failed to create '" + name + "' memory block: exclusive access/checkout required");
			return null;
		}
		MemoryBlock firstBlock = null;
		try {
			int blockNum = 0;

			// While the block is larger that the maximum allowed size, create smaller
			// blocks.
			long blockLength = 0; // special case first time through loop, don't change start address
			while (dataLength > 0) {
				start = start.add(blockLength);
				blockLength = Math.min(dataLength, Memory.MAX_INITIALIZED_BLOCK_SIZE);
				String blockName = getBlockName(name, blockNum);
				monitor.setMessage(
					"Creating memory block \"" + blockName + "\" at 0x" + start + "...");
				try {
					MemoryBlock block = memory.createInitializedBlock(blockName, start, dataInput,
						blockLength, monitor, false);
					setBlockAttributes(block, comment, source, r, w, x);

					renameFragment(start, blockName);
					firstBlock = firstBlock == null ? block : firstBlock;
				}
				catch (MemoryConflictException memExc) {
					handleMemoryConflict(blockName, start, dataInput, blockLength, comment, source,
						r, w, x);
				}
				blockNum++;
				dataLength -= blockLength;
			}

			return firstBlock;
		}
		catch (LockException e) {
			throw new RuntimeException(e); //this should never happen
		}
		catch (CancelledException e) {
			// return null
		}
		catch (DuplicateNameException e) {
			// TODO: This is BAD! Who should handle name conflict?
			throw new RuntimeException(e);
		}
		return null;
	}

	private String getBlockName(String name, int blockNum) {
		if (blockNum == 0) {
			return name;
		}
		return name + "." + blockNum;
	}

	private void handleMemoryConflict(String name, Address start, InputStream dataInput,
			long dataLength, String comment, String source, boolean r, boolean w, boolean x)
			throws AddressOverflowException {
		Address end = start.addNoWrap(dataLength - 1);

		List<AddressLabelInfo> removedSymbolList = resolveConflicts(start, end);

		//Create an address set consisting of the
		//address range of the new block that we want to create
		//
		AddressSet set = new AddressSet(start, end);

		//All uninitialized blocks that were in the way
		//have been removed. All that remains is initialized blocks.
		//We do not touch the boundaries of these. Therefore,
		//remove their ranges from our address set.
		//
		MemoryBlock[] existingBlocks = memory.getBlocks();
		for (int i = 0; i < existingBlocks.length; ++i) {
			set.deleteRange(existingBlocks[i].getStart(), existingBlocks[i].getEnd());
		}

		appendMessage("WARNING!!\n\tMemory block [" + name +
			"] has caused an address collision.\n\tAddress range automatically changed from [" +
			start + "," + end + "] to " + set.toString());

		ArrayList<MemoryBlock> newBlocks = createNeededBlocks(name, comment, source, r, w, x, set);

		restoreSymbols(removedSymbolList);

		boolean shouldOverwriteBlock = true;
		if (existingBlocks.length > 0) {
			shouldOverwriteBlock = handler.allowOverwrite(start, end);
		}

		//TODO: collect all user references in (start,end)

		//if we get a conflict, then we need to read the bytes out of the stream...
		byte[] data = new byte[(int) dataLength];
		try {
			dataInput.read(data);
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}

		restoreBytes(start, end, newBlocks, shouldOverwriteBlock, data);
	}

	private void restoreBytes(Address start, Address end, ArrayList<MemoryBlock> newBlocks,
			boolean shouldOverwriteBlock, byte[] data) {
		if (shouldOverwriteBlock) {
			// clear any code units they may exists in the overlapping area...
			//
			listing.clearCodeUnits(start, end, false);
			appendMessage("Cleared code units from start=" + "0x" + start.toString() + " to end=" +
				"0x" + end.toString());
			try {
				memory.setBytes(start, data);

				appendMessage("Overwrote memory from start=" + start + " length=" + data.length);
			}
			catch (MemoryAccessException exc) {
				appendMessage("Error Overwriting Bytes[1]: " + exc);
			}
		}
		else { // or just the new memory blocks that were created...
			try {
				for (int i = 0; i < newBlocks.size(); ++i) {
					MemoryBlock mb = newBlocks.get(i);
					memory.setBytes(mb.getStart(), data, (int) mb.getStart().subtract(start),
						(int) mb.getSize());
				}
			}
			catch (MemoryAccessException exc) {
				appendMessage("Error Overwriting Bytes[2]: " + exc);
			}
		}
	}

	private void restoreSymbols(List<AddressLabelInfo> removedSymbolList) {
		// restore deleted symbols
		for (AddressLabelInfo info : removedSymbolList) {
			try {
				Symbol symbol = symbolTable.createLabel(info.getAddress(), info.getLabel(),
					info.getScope(), info.getSource());
				if (info.isPrimary()) {
					symbol.setPrimary();
				}
			}
			catch (Exception e) {
				// We tried
			}
		}
	}

	private ArrayList<MemoryBlock> createNeededBlocks(String name, String comment, String source,
			boolean r, boolean w, boolean x, AddressSet set) {
		//Now, create blocks for the remaining ranges in our address set
		//
		ArrayList<MemoryBlock> newBlocks = new ArrayList<>();
		AddressRangeIterator iter = set.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			byte[] bytes = new byte[(int) range.getLength()];

			MemoryBlock newBlock = null;
			try {
				newBlock = memory.createInitializedBlock(name, range.getMinAddress(),
					new ByteArrayInputStream(bytes), bytes.length, null, false);
				setBlockAttributes(newBlock, comment, source, r, w, x);
			}
			catch (CancelledException e) {
			}
			catch (LockException e) {
				throw new RuntimeException(e); //this should never happen
			}
			catch (DuplicateNameException e) {
				throw new RuntimeException(e);
			}
			catch (MemoryConflictException e) {
				throw new RuntimeException(e); //this should never happen
			}
			catch (AddressOverflowException e) {
				throw new RuntimeException(e); //this should never happen
			}

			if (newBlock != null) {
				newBlock.setRead(r);
				newBlock.setWrite(w);
				newBlock.setExecute(x);

				newBlocks.add(newBlock);
			}
		}
		return newBlocks;
	}

	private List<AddressLabelInfo> resolveConflicts(Address start, Address end) {
		List<AddressLabelInfo> symbolList = new ArrayList<>();
		MemoryBlock[] blocks = memory.getBlocks();

		for (int i = 0; i < blocks.length; ++i) {
			if (blocks[i].isInitialized()) {
				continue;
			}

			int caseVal = getMemoryConflictCase(start, end, blocks[i]);

			try {
				switch (caseVal) {
					case MEMORY_CONFLICT_REMOVE_1ST_HALF: {
						memory.split(blocks[i], end.add(1));
						MemoryBlock secondHalf = memory.getBlock(end.add(1));
						try {
							secondHalf.setName(blocks[i].getName());
						}
						catch (DuplicateNameException e) {
							throw new AssertException(e);
						}
						loadSymbolsFromBlock(symbolList, blocks[i]);
						memory.removeBlock(blocks[i], TaskMonitorAdapter.DUMMY_MONITOR);
						blocks[i] = secondHalf;
						break;
					}
					case MEMORY_CONFLICT_REMOVE_2ND_HALF: {
						memory.split(blocks[i], start);
						MemoryBlock secondHalf = memory.getBlock(start);
						loadSymbolsFromBlock(symbolList, secondHalf);
						memory.removeBlock(secondHalf, TaskMonitorAdapter.DUMMY_MONITOR);
						blocks[i] = memory.getBlock(blocks[i].getStart());
						break;
					}
					case MEMORY_CONFLICT_REMOVE_WHOLE: {
						loadSymbolsFromBlock(symbolList, blocks[i]);
						memory.removeBlock(blocks[i], TaskMonitorAdapter.DUMMY_MONITOR);
						break;
					}
					case MEMORY_CONFLICT_REMOVE_MIDDLE: {
						memory.split(blocks[i], start);
						MemoryBlock middleBlock = memory.getBlock(start);
						memory.split(middleBlock, end.add(1));
						MemoryBlock endBlock = memory.getBlock(end.add(1));
						try {
							endBlock.setName(blocks[i].getName());
						}
						catch (DuplicateNameException e) {
							throw new AssertException(e);
						}
						loadSymbolsFromBlock(symbolList, middleBlock);
						memory.removeBlock(middleBlock, TaskMonitorAdapter.DUMMY_MONITOR);
						break;
					}
					case MEMORY_CONFLICT_IGNORE: {
						break;
					}
					default:
						throw new RuntimeException(
							"Unable to resolve memory confliction exception.");
				}
			}
			catch (MemoryBlockException e) {
			}
			catch (LockException e) {
			}
			catch (NotFoundException e) {
			}
		}
		return symbolList;
	}

	private void loadSymbolsFromBlock(List<AddressLabelInfo> symbolList, MemoryBlock block) {
		SymbolIterator it = symbolTable.getSymbolIterator(block.getStart(), true);
		Address end = block.getEnd();
		while (it.hasNext()) {
			Symbol symbol = it.next();
			if (symbol.getAddress().compareTo(end) > 0) {
				break;
			}
			symbolList.add(new AddressLabelInfo(symbol));
		}
	}

	/**
	 * Creates an initialized overlay memory block using the specified input stream.
	 *
	 * @param name       name of the block
	 * @param start      start address of the block
	 * @param dataInput  an input stream containing the bytes for the block
	 * @param dataLength length of the block
	 * @param comment    comment for the block
	 * @param source     source of the block, where it originated
	 * @param r          is block read-only?
	 * @param w          is block writeable?
	 * @param x          is block executable?
	 * @param monitor    the task monitor
	 *
	 * @return the newly created memory block
	 */
	public MemoryBlock createOverlayBlock(String name, Address start, InputStream dataInput,
			long dataLength, String comment, String source, boolean r, boolean w, boolean x,
			TaskMonitor monitor) throws AddressOverflowException, DuplicateNameException {

		if (!memory.getProgram().hasExclusiveAccess()) {
			appendMessage("Failed to create '" + name +
				"' overlay memory block, exclusive access/checkout required");
			return null;
		}
		try {
			MemoryBlock block =
				memory.createInitializedBlock(name, start, dataInput, dataLength, monitor, true);

			setBlockAttributes(block, comment, source, r, w, x);

			renameFragment(block.getStart(), name);

			return block;
		}
		catch (LockException e) {
			throw new AssertException(e); //this should never happen
		}
		catch (CancelledException e) {
		}
		catch (MemoryConflictException e) {
			throw new AssertException(e); // should never happen
		}
		return null;
	}

	private void setBlockAttributes(MemoryBlock block, String comment, String source, boolean r,
			boolean w, boolean x) {
		block.setComment(comment);
		block.setSourceName(source);
		block.setRead(r);
		block.setWrite(w);
		block.setExecute(x);
	}

	private int getMemoryConflictCase(Address start, Address end, MemoryBlock block) {
		if (block.isInitialized()) {
			return MEMORY_CONFLICT_IGNORE;
		}

		Address blockStart = block.getStart();
		Address blockEnd = block.getEnd();

		AddressSpace startSpace = start.getAddressSpace();
		if (!startSpace.equals(end.getAddressSpace())) {
			return MEMORY_CONFLICT_IGNORE;
		}
		if (!startSpace.equals(blockStart.getAddressSpace())) {
			return MEMORY_CONFLICT_IGNORE;
		}

		if (start.compareTo(blockStart) <= 0 && end.compareTo(blockEnd) >= 0) {
			return MEMORY_CONFLICT_REMOVE_WHOLE;
		}
		if (blockStart.compareTo(start) < 0 && blockEnd.compareTo(end) > 0) {
			return MEMORY_CONFLICT_REMOVE_MIDDLE;
		}
		if (start.compareTo(blockStart) <= 0 && end.compareTo(blockStart) >= 0 &&
			end.compareTo(blockEnd) < 0) {
			return MEMORY_CONFLICT_REMOVE_1ST_HALF;
		}
		if (start.compareTo(blockStart) > 0 && start.compareTo(blockEnd) <= 0 &&
			end.compareTo(blockEnd) >= 0) {
			return MEMORY_CONFLICT_REMOVE_2ND_HALF;
		}
		//if block does not intersect
		if (start.compareTo(blockEnd) > 0 || end.compareTo(blockStart) < 0) {
			return MEMORY_CONFLICT_IGNORE;
		}
		return MEMORY_CONFLICT_UNKNOWN;
	}

	private void appendMessage(String msg) {
		if (messages.length() != 0) {
			messages.append('\n');
		}
		messages.append(msg);
	}

	private void renameFragment(Address blockStart, String blockName) {
		String[] treeNames = listing.getTreeNames();
		for (int i = 0; i < treeNames.length; ++i) {
			try {
				ProgramFragment frag = listing.getFragment(treeNames[i], blockStart);
				frag.setName(blockName);
			}
			catch (DuplicateNameException e) {
			}
		}
	}

}
