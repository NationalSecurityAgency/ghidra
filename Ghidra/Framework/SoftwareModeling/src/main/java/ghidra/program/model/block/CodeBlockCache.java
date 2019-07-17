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
package ghidra.program.model.block;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressObjectMap;

/**
 * Provides a subroutine cache implementation.
 *
 * 
 * Created: February 28, 2002
 */
class CodeBlockCache extends AddressObjectMap {

	CodeBlockCache() {
		super();
	}
	
    /**
     * Get the cached block whose first entry-point is addr. 
     * This method is slightly more efficient than getBlockWithEntryAt,
     * however, it should only be used when the cached block has exactly
     * one entry-point.
     * @return the block with an entry-point address of addr, or null of
     * the block was not found.
     */
    CodeBlock getBlockAt(Address addr){
        Object[] blocks = getObjects(addr);
        for (int i=0; i < blocks.length; i++) {
            CodeBlock block = (CodeBlock) blocks[i];
            Address startAddr = block.getFirstStartAddress();
            if (startAddr.equals(addr)) {
                return block;
            }
        }
        return null;
    }


    /**
     * Get the cached block which has an entry-point of addr.
     * @return the block with an entry-point address of addr, or null of
     * the block was not found.
     */
    CodeBlock getBlockWithEntryAt(Address addr){
        Object[] blocks = getObjects(addr);
        for (int i=0; i < blocks.length; i++) {
            CodeBlock block = (CodeBlock) blocks[i];
            Address starts[] = block.getStartAddresses();
            for (int j=0; j < starts.length; j++) {
                if (starts[j].equals(addr)) {
                    return block;
                }
            }
        }
        return null;
    }
    
    /**
     * Get all cached blocks which contain addr. 
     * @return  blocks that contain addr if they are in the cache.
     *          Otherwise, return null.
     */
    CodeBlock[] getBlocksContaining(Address addr){
    	Object[] objs = getObjects(addr);
        int length = objs.length;
        if (length == 0){
            return null;
        }
        CodeBlock[] blocks = new CodeBlock[objs.length];
    	System.arraycopy(objs, 0, blocks, 0, length);
        return blocks;
    }

    /**
     * Get the first block which contains addr.
     * @return  the block whose entry point is minimum among all
     *          blocks that contain addr and are in the cache.
     *          Otherwise, return null.
     */
    CodeBlock getFirstBlockContaining(Address addr){
        CodeBlock[] blocks = getBlocksContaining(addr);
        if (blocks == null)
            return null;
        if (blocks.length == 1)
            return blocks[0];

        int firstIndex = -1;
        Address minAddr = null;
        for (int i=0; i < blocks.length; i++) {
            if (minAddr == null ||
            	minAddr.compareTo(blocks[i].getFirstStartAddress()) > 0) {
                minAddr = blocks[i].getFirstStartAddress();
                firstIndex = i;
            }
        }
        return blocks[firstIndex];
    }
}
