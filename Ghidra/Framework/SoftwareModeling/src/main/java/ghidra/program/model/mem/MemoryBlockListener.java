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
package ghidra.program.model.mem;

import ghidra.program.model.address.Address;

/**
 * Methods for a listener that is called when changes are made to a
 * MemoryBlock.
 * 
 * 
 */
public interface MemoryBlockListener {
	/**
	 * Notification the name changed.
	 * @param block affected block
	 * @param oldName old name
	 * @param newName new name
	 */
	public void nameChanged(MemoryBlock block, String oldName, String newName);

	/**
	 * Notification that the block's comment changed.
	 * @param block affected block 
	 * @param oldComment old comment; may be null
	 * @param newComment new comment; may be null
	 */
	public void commentChanged(MemoryBlock block,
                                String oldComment,
                                String newComment);

	/**
	 * Notification the block's read attribute has changed.
	 * 
	 * @param block affected block
	 * @param isRead true means the block is marked as readable
	 */
	public void readStatusChanged(MemoryBlock block, boolean isRead);
    
    /**
     * Notification that the block's write attribute has changed.
     * @param block affected block
     * @param isWrite true means the block is marked as writable
     */
    public void writeStatusChanged(MemoryBlock block, boolean isWrite);
    
    /**
     * Notification that the block's execute attribute has changed.
     * @param block affected block
     * @param isExecute true means the block is marked as executable
     */
    public void executeStatusChanged(MemoryBlock block, boolean isExecute);
	
	/**
	 * Notification that the source of the block has changed.
	 * @param block affected block
	 * @param oldSource old source 
	 * @param newSource new source
	 */
	public void sourceChanged(MemoryBlock block,
                                String oldSource,
                                String newSource);
	/**
	 * Notification that the source offset has changed.
	 * @param block affected block
	 * @param oldOffset old offset
	 * @param newOffset new offset
	 */
	public void sourceOffsetChanged(MemoryBlock block,
                                    long oldOffset,
                                    long newOffset);
	/**
	 * Notification that bytes changed in the block.
	 * @param block affected block
	 * @param addr starting address of the change
	 * @param oldData old byte values
	 * @param newData new byte values
	 */
	public void dataChanged(MemoryBlock block,
                            Address addr,
                            byte[] oldData,
                            byte[] newData);	
}
