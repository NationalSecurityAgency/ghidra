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

import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/** 
 * Convenience methods for creating memory blocks.
 */
public class MemoryBlockUtils {

	/**
	 * Creates a new uninitialized memory block.
	 * @param program the program in which to create the block.
	 * @param isOverlay if true, the block will be created in a new overlay space for that block
	 * @param name the name of the new block.
	 * @param start the starting address of the new block.
	 * @param length the length of the new block
	 * @param comment the comment text to associate with the new block.
	 * @param source the source of the block (This field is not well defined - currently another comment)
	 * @param r the read permission for the new block.
	 * @param w the write permission for the new block.
	 * @param x the execute permission for the new block.
	 * @param log a {@link MessageLog} for appending error messages
	 * @return the newly created block or null if the operation failed.
	 */
	public static MemoryBlock createUninitializedBlock(Program program, boolean isOverlay,
			String name, Address start, long length, String comment, String source, boolean r,
			boolean w, boolean x, MessageLog log) {

		Memory memory = program.getMemory();
		try {
			MemoryBlock block = memory.createUninitializedBlock(name, start, length, isOverlay);
			setBlockAttributes(block, comment, source, r, w, x);
			adjustFragment(program, block.getStart(), name);
			return block;
		}
		catch (LockException e) {
			log.appendMsg("Failed to create memory block: exclusive lock/checkout required");
		}
		catch (Exception e) {
			log.appendMsg("Failed to create '" + name + "' memory block: " + e.getMessage());
		}
		return null;
	}

	/**
	 * Create a new initialized memory block.  Initialized to all zeros.
	 * @param program the program in which to create the block.
	 * @param isOverlay if true, the block will be created in a new overlay space for that block
	 * @param name the name of the new block.
	 * @param start the starting address of the new block.
	 * @param length the length of the new block
	 * @param comment the comment text to associate with the new block.
	 * @param source the source of the block (This field is not well defined - currently another comment)
	 * @param r the read permission for the new block.
	 * @param w the write permission for the new block.
	 * @param x the execute permission for the new block.
	 * @param log a {@link MessageLog} for appending error messages
	 * @return the newly created block or null if the operation failed.
	 */
	public static MemoryBlock createInitializedBlock(Program program, boolean isOverlay,
			String name, Address start, long length, String comment, String source, boolean r,
			boolean w, boolean x, MessageLog log) {

		Memory memory = program.getMemory();
		try {
			MemoryBlock block = memory.createInitializedBlock(name, start, null, length,
				TaskMonitor.DUMMY, isOverlay);
			setBlockAttributes(block, comment, source, r, w, x);
			adjustFragment(program, block.getStart(), name);
			return block;
		}
		catch (LockException e) {
			log.appendMsg("Failed to create memory block: exclusive lock/checkout required");
		}
		catch (Exception e) {
			log.appendMsg("Failed to create '" + name + "' memory block: " + e.getMessage());
		}
		return null;
	}

	/**
	 * Creates a new bit mapped memory block. (A bit mapped block is a block where each byte value
	 * is either 1 or 0 and the value is taken from a bit in a byte at some other address in memory)
	 * 
	 * @param program the program in which to create the block.
	 * @param name the name of the new block.
	 * @param start the starting address of the new block.
	 * @param base the address of the region in memory to map to.
	 * @param length the length of the new block
	 * @param comment the comment text to associate with the new block.
	 * @param source the source of the block (This field is not well defined - currently another comment)
	 * @param r the read permission for the new block.
	 * @param w the write permission for the new block.
	 * @param x the execute permission for the new block.
	 * @param overlay create overlay block if true otherwise a normal mapped block will be created
	 * @param log a {@link StringBuffer} for appending error messages
	 * @return the new created block
	 */
	public static MemoryBlock createBitMappedBlock(Program program, String name, Address start,
			Address base, int length, String comment, String source, boolean r, boolean w,
			boolean x, boolean overlay, MessageLog log) {

		Memory memory = program.getMemory();
		try {

			MemoryBlock block = memory.createBitMappedBlock(name, start, base, length, overlay);

			setBlockAttributes(block, comment, source, r, w, x);
			adjustFragment(program, start, name);
			return block;
		}
		catch (LockException e) {
			log.appendMsg("Failed to create '" + name +
				"'bit mapped memory block: exclusive lock/checkout required");
		}
		catch (Exception e) {
			log.appendMsg("Failed to create '" + name + "' mapped memory block: " + e.getMessage());
		}
		return null;
	}

	/**
	 * Creates a new byte mapped memory block with a 1:1 byte mapping scheme. 
	 * (A byte mapped block is a block where each byte value
	 * is taken from a byte at some other address in memory)
	 * 
	 * @param program the program in which to create the block.
	 * @param name the name of the new block.
	 * @param start the starting address of the new block.
	 * @param base the address of the region in memory to map to.
	 * @param length the length of the new block
	 * @param comment the comment text to associate with the new block.
	 * @param source the source of the block (This field is not well defined - currently another comment)
	 * @param r the read permission for the new block.
	 * @param w the write permission for the new block.
	 * @param x the execute permission for the new block.
	 * @param overlay create overlay block if true otherwise a normal mapped block will be created
	 * @param log a {@link MessageLog} for appending error messages
	 * @return the new created block
	 */
	public static MemoryBlock createByteMappedBlock(Program program, String name, Address start,
			Address base, int length, String comment, String source, boolean r, boolean w,
			boolean x, boolean overlay, MessageLog log) {

		Memory memory = program.getMemory();
		try {

			MemoryBlock block = memory.createByteMappedBlock(name, start, base, length, overlay);

			setBlockAttributes(block, comment, source, r, w, x);
			adjustFragment(program, start, name);
			return block;
		}
		catch (LockException e) {
			log.appendMsg("Failed to create '" + name +
				"' byte mapped memory block: exclusive lock/checkout required");
		}
		catch (Exception e) {
			log.appendMsg("Failed to create '" + name + "' mapped memory block: " + e.getMessage());
		}
		return null;
	}

	/**
	 * Creates a new initialized block in memory using the bytes from a {@link FileBytes} object.
	 * If there is a conflict when creating this block (some other block occupies at least some
	 * of the addresses that would be occupied by the new block), then an attempt will be made
	 * to create the new block in an overlay.
	 * 
	 * @param program the program in which to create the block.
	 * @param isOverlay if true, the block will be created in a new overlay space for that block
	 * @param name the name of the new block.
	 * @param start the starting address of the new block.
	 * @param fileBytes the {@link FileBytes} object that supplies the bytes for this block.
	 * @param offset the offset into the {@link FileBytes} object where the bytes for this block reside.
	 * @param length the length of the new block
	 * @param comment the comment text to associate with the new block.
	 * @param source the source of the block (This field is not well defined - currently another comment)
	 * @param r the read permission for the new block.
	 * @param w the write permission for the new block.
	 * @param x the execute permission for the new block.
	 * @param log a {@link MessageLog} for appending error messages
	 * @return the new created block
	 * @throws AddressOverflowException if the address 
	 */
	public static MemoryBlock createInitializedBlock(Program program, boolean isOverlay,
			String name, Address start, FileBytes fileBytes, long offset, long length,
			String comment, String source, boolean r, boolean w, boolean x, MessageLog log)
			throws AddressOverflowException {

		if (!program.hasExclusiveAccess()) {
			log.appendMsg("Failed to create memory block: exclusive access/checkout required");
			return null;
		}
		MemoryBlock block;
		try {
			try {
				block = program.getMemory().createInitializedBlock(name, start, fileBytes, offset,
					length, isOverlay);
			}
			catch (MemoryConflictException e) {
				block = program.getMemory()
						.createInitializedBlock(name, start, fileBytes, offset, length, true);
				log.appendMsg("Conflict attempting to create memory block: " + name +
					" at address " + start.toString() + " Created block in new overlay instead");
			}
		}
		catch (LockException | MemoryConflictException e) {
			throw new RuntimeException(e);
		}

		setBlockAttributes(block, comment, source, r, w, x);
		adjustFragment(program, block.getStart(), name);
		return block;
	}

	/**
	 * Creates a new initialized block in memory using the bytes from the given input stream.
	 * If there is a conflict when creating this block (some other block occupies at least some
	 * of the addresses that would be occupied by the new block), then an attempt will be made
	 * to create the new block in an overlay.
	 * 
	 * @param program the program in which to create the block.
	 * @param isOverlay if true, the block will be created in a new overlay space for that block
	 * @param name the name of the new block.
	 * @param start the starting address of the new block.
	 * @param dataInput the {@link InputStream} object that supplies the bytes for this block.
	 * @param dataLength the length of the new block
	 * @param comment the comment text to associate with the new block.
	 * @param source the source of the block (This field is not well defined - currently another comment)
	 * @param r the read permission for the new block.
	 * @param w the write permission for the new block.
	 * @param x the execute permission for the new block.
	 * @param log a {@link MessageLog} for appending error messages
	 * @param monitor the monitor for canceling this potentially long running operation.
	 * @return the new created block
	 * @throws AddressOverflowException if the address 
	 */
	public static MemoryBlock createInitializedBlock(Program program, boolean isOverlay,
			String name, Address start, InputStream dataInput, long dataLength, String comment,
			String source, boolean r, boolean w, boolean x, MessageLog log, TaskMonitor monitor)
			throws AddressOverflowException {

		if (!program.hasExclusiveAccess()) {
			log.appendMsg("Failed to create memory block: exclusive access/checkout required");
			return null;
		}

		Memory memory = program.getMemory();
		MemoryBlock block;
		try {
			try {
				block = memory.createInitializedBlock(name, start, dataInput, dataLength, monitor,
					isOverlay);
			}
			catch (MemoryConflictException e) {
				block = memory.createInitializedBlock(name, start, dataInput, dataLength, monitor,
					true);
				log.appendMsg("Conflict attempting to create memory block: " + name +
					" at address " + start.toString() + " Created block in new overlay instead");
			}
		}
		catch (LockException | MemoryConflictException e) {
			throw new RuntimeException(e);
		}
		catch (CancelledException e) {
			return null;
		}

		setBlockAttributes(block, comment, source, r, w, x);
		adjustFragment(program, block.getStart(), block.getName());
		return block;
	}

	/**
	 * Adjusts the name of the fragment at the given address to the given name.
	 * @param program the program whose fragment is to be renamed.
	 * @param address the address of the fragment to be renamed.
	 * @param name the new name for the fragment.
	 */
	public static void adjustFragment(Program program, Address address, String name) {
		Listing listing = program.getListing();
		String[] treeNames = listing.getTreeNames();
		for (String treeName : treeNames) {
			try {
				ProgramFragment frag = listing.getFragment(treeName, address);
				frag.setName(name);
			}
			catch (DuplicateNameException e) {
				Msg.warn(MemoryBlockUtils.class,
					"Could not rename fragment to match newly created block because of name conflict");
			}
		}
	}

	/**
	 * Creates a new {@link FileBytes} object using all the bytes from a {@link ByteProvider}
	 * @param program the program in which to create a new FileBytes object
	 * @param provider the ByteProvider from which to get the bytes.
	 * @return the newly created FileBytes object.
	 * @param monitor the monitor for canceling this potentially long running operation.
	 * @throws IOException if an IOException occurred.
	 */
	public static FileBytes createFileBytes(Program program, ByteProvider provider,
			TaskMonitor monitor) throws IOException, CancelledException {
		return createFileBytes(program, provider, 0, provider.length(), monitor);
	}

	/**
	 * Creates a new {@link FileBytes} object using a portion of the bytes from a {@link ByteProvider}
	 * @param program the program in which to create a new FileBytes object
	 * @param provider the ByteProvider from which to get the bytes.
	 * @param offset the offset into the ByteProvider from which to start loading bytes.
	 * @param length the number of bytes to load
	 * @param monitor the monitor for canceling this potentially long running operation.
	 * @return the newly created FileBytes object.
	 * @throws IOException if an IOException occurred.
	 * @throws CancelledException if the user cancelled the operation
	 */
	public static FileBytes createFileBytes(Program program, ByteProvider provider, long offset,
			long length, TaskMonitor monitor) throws IOException, CancelledException {
		Memory memory = program.getMemory();
		try (InputStream fis = provider.getInputStream(offset)) {
			return memory.createFileBytes(provider.getName(), offset, length, fis, monitor);
		}
	}

	private static void setBlockAttributes(MemoryBlock block, String comment, String source,
			boolean r, boolean w, boolean x) {
		block.setComment(comment);
		block.setSourceName(source);
		block.setRead(r);
		block.setWrite(w);
		block.setExecute(x);
	}
}
