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
package ghidra.program.util;

import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.SystemUtilities;

/**
 * <CODE>MemoryBlockDiff</CODE> determines the types of differences between two memory blocks.
 */
public class MemoryBlockDiff {
	
	public static final int NAME          = 0x001;
	public static final int START_ADDRESS = 0x002;
	public static final int END_ADDRESS   = 0x004;
	public static final int SIZE          = 0x008;
	public static final int READ          = 0x010;
	public static final int WRITE         = 0x020;
	public static final int EXECUTE       = 0x040;
	public static final int VOLATILE      = 0x080;
	public static final int TYPE          = 0x100;
	public static final int INIT          = 0x200;
	public static final int SOURCE        = 0x400;
	public static final int COMMENT       = 0x800;
	public static final int ALL           = 0xFFF;
	
	private MemoryBlock block1;
	private MemoryBlock block2;
	private int diffFlags;
	
	/**
	 * Constructor. <CODE>MemoryBlockDiff</CODE> determines the types of differences 
	 * between two memory blocks.
	 * @param block1 the first program's memory block
	 * @param block2 the second program's memory block
	 */
	public MemoryBlockDiff(MemoryBlock block1, MemoryBlock block2) {
		this.block1 = block1;
		this.block2 = block2;
		diffFlags = getDiffFlags();
	}

	MemoryBlock getBlock1() {
		return block1;
	}
	
	MemoryBlock getBlock2() {
		return block2;
	}
	
	/**
	 * Returns true if the memory block names differ.
	 */
	public boolean isNameDifferent() {
		return (diffFlags & NAME) != 0;
	}
	
	/**
	 * Returns true if the start addresses of the memory blocks differ.
	 */
	public boolean isStartAddressDifferent() {
		return (diffFlags & START_ADDRESS) != 0;
	}
	
	/**
	 * Returns true if the end addresses of the memory blocks differ.
	 */
	public boolean isEndAddressDifferent() {
		return (diffFlags & END_ADDRESS) != 0;
	}
	
	/**
	 * Returns true if the sizes of the memory blocks differ.
	 */
	public boolean isSizeDifferent() {
		return (diffFlags & SIZE) != 0;
	}
	
	/**
	 * Returns true if the memory blocks Read flags differ.
	 */
	public boolean isReadDifferent() {
		return (diffFlags & READ) != 0;
	}
	
	/**
	 * Returns true if the memory blocks Write flags differ.
	 */
	public boolean isWriteDifferent() {
		return (diffFlags & WRITE) != 0;
	}
	
	/**
	 * Returns true if the memory blocks Execute flags differ.
	 */
	public boolean isExecDifferent() {
		return (diffFlags & EXECUTE) != 0;
	}
	
	/**
	 * Returns true if the memory blocks Volatile flags differ.
	 */
	public boolean isVolatileDifferent() {
		return (diffFlags & VOLATILE) != 0;
	}
	
	/**
	 * Returns true if the type for the memory blocks differ.
	 */
	public boolean isTypeDifferent() {
		return (diffFlags & TYPE) != 0;
	}
	
	/**
	 * Returns true if the initialization of the memory blocks isn't the same.
	 */
	public boolean isInitDifferent() {
		return (diffFlags & INIT) != 0;
	}
	
	/**
	 * Returns true if the source for the memory blocks differ.
	 */
	public boolean isSourceDifferent() {
		return (diffFlags & SOURCE) != 0;
	}
	
	/**
	 * Returns true if the comments on the memory blocks differ.
	 */
	public boolean isCommentDifferent() {
		return (diffFlags & COMMENT) != 0;
	}
	
	/**
	 * Gets a string representation of the types of memory differences for this MemoryBlockDiff.
	 */
	public String getDifferencesAsString() {
		StringBuffer buf = new StringBuffer();
		if((diffFlags & NAME) != 0) {
			buf.append("Name ");
		}
		if((diffFlags & START_ADDRESS) != 0) {
			buf.append("StartAddress ");
		}
		if((diffFlags & END_ADDRESS) != 0) {
			buf.append("EndAddress ");
		}
		if((diffFlags & SIZE) != 0) {
			buf.append("Size ");
		}
		if((diffFlags & READ) != 0) {
			buf.append("R ");
		}
		if((diffFlags & WRITE) != 0) {
			buf.append("W ");
		}
		if((diffFlags & EXECUTE) != 0) {
			buf.append("X ");
		}
		if((diffFlags & VOLATILE) != 0) {
			buf.append("Volatile ");
		}
		if((diffFlags & TYPE) != 0) {
			buf.append("Type ");
		}
		if((diffFlags & INIT) != 0) {
			buf.append("Initialized ");
		}
		if((diffFlags & SOURCE) != 0) {
			buf.append("Source ");
		}
		if((diffFlags & COMMENT) != 0) {
			buf.append("Comment ");
		}
		return buf.toString();
	}
	
	/**
	 * Gets an integer value that has bits set as flags indicating the types of differences
	 * that exist between the two memory blocks.
	 * @param block1 the first program's memory block
	 * @param block2 the second program's memory block
	 * @return the memory difference flags
	 */
	private int getDiffFlags() {
		if (block1 == null) {
			if (block2 == null) {
				return 0;
			}
			return ALL;
		}
		if (block2 == null) {
			return ALL;
		}
		
		int flags = 0;
		if(!block1.getName().equals(block2.getName())) {
			flags |= NAME;
		}
		if (!block1.getStart().equals(block2.getStart())) {
			flags |= START_ADDRESS;
		}
		if (!block1.getEnd().equals(block2.getEnd())) {
			flags |= END_ADDRESS;
		}
		if (block1.getSize() != block2.getSize()) {
			flags |= SIZE;
		}
		if (block1.isRead() != block2.isRead()) {
			flags |= READ;
		}
		if (block1.isWrite() != block2.isWrite()) {
			flags |= WRITE;
		}
		if (block1.isExecute() != block2.isExecute()) {
			flags |= EXECUTE;
		}
		if (block1.isVolatile() != block2.isVolatile()) {
			flags |= VOLATILE;
		}
		if (!block1.getType().equals(block2.getType())) {
			flags |= TYPE;
		}
		if (block1.isInitialized() != block2.isInitialized()) {
			flags |= INIT;
		}
		if (!SystemUtilities.isEqual(block1.getSourceName(), block2.getSourceName())) {
			flags |= SOURCE;
		}
		if (!SystemUtilities.isEqual(block1.getComment(), block2.getComment())) {
			flags |= COMMENT;
		}
		return flags;
	}
}
