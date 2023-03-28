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
import java.util.*;

import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.plugin.core.format.*;

/**
 * Generates a map between bytes in memory and indexes.  Extra indexes are inserted to
 * make each block to take up an uniform number of indexes such that the number of indexes
 * in each block is a multiple of the number of bytes per line.
 */
public class IndexMap {

	private ByteBlockSet blockSet;
	private TreeMap<BigInteger, BlockInfo> blockInfoMap = new TreeMap<BigInteger, BlockInfo>();
	private BigInteger numIndexes;
	private BigInteger bytesInLine;

	IndexMap() {
		this(new EmptyByteBlockSet(), 16, 0);
	}

	/**
	 * Create an IndexMap with the given set of blocks, the bytes per line, and the user
	 * set blockOffset.
	 * @param blockSet the set of byte blocks
	 * @param bytesPerLine  the number of bytes displayed per line
	 * @param blockOffset the number of byte positions to skip when rendering the first line of
	 * the block. (If a block starts at address 6, we skip 6 byte positions so the entire block
	 * is positioned as if the block started at 0
	 */
	IndexMap(ByteBlockSet blockSet, int bytesPerLine, int blockOffset) {

		this.blockSet = blockSet;
		ByteBlock[] blocks = blockSet.getBlocks();
		this.bytesInLine = BigInteger.valueOf(bytesPerLine);

		BigInteger nextStart = BigInteger.ZERO;
		for (int i = 0; i < blocks.length; i++) {
			int blockPadding =
				((blocks[i].getAlignment(bytesPerLine) + blockOffset) % bytesPerLine);
			BigInteger blockStart = nextStart.add(BigInteger.valueOf(blockPadding));
			BigInteger blockEnd = blockStart.add(blocks[i].getLength());
			int remainder = blockEnd.remainder(bytesInLine).intValue();
			BigInteger endIndex =
				remainder == 0 ? blockEnd
						: blockEnd.add(BigInteger.valueOf(bytesPerLine -
							remainder));
			BigInteger endLayoutIndex = endIndex.divide(bytesInLine);
			BlockInfo info = new BlockInfo(blocks[i], nextStart, blockStart, blockEnd, endIndex);
			blockInfoMap.put(endLayoutIndex, info);
			nextStart = endIndex.add(bytesInLine);
		}
		numIndexes = nextStart.divide(bytesInLine).subtract(BigInteger.ONE);
		if (nextStart.equals(BigInteger.ZERO)) {
			numIndexes = BigInteger.ZERO;
		}

	}

	/**
	 * Returns the total number of indexes in this map.
	 * @return The number byte indexes (possible display positions) in this index map (includes
	 *  offset padding and separator positions. This will always be a muliple of the number of
	 *  bytes displayed per line.
	 */
	BigInteger getNumIndexes() {
		return numIndexes;
	}

	/**
	 * Returns the number of bytes per line.
	 * @return  the number of bytes per line
	 */
	int getBytesPerLine() {
		return bytesInLine.intValue();
	}

	/**
	 * Returns block location information about the given index and fieldOffset.
	 * @param index The line index
	 * @param fieldOffset the field offset (in bytes) from the beginning of the line. 
	 * @return The ByteBlockInfo object that contains the block and offset into that block
	 * that is the resulting byte value.
	 */
	IndexedByteBlockInfo getBlockInfo(BigInteger index, int fieldOffset) {
		SortedMap<BigInteger, BlockInfo> tailMap = blockInfoMap.tailMap(index);
		if (tailMap.isEmpty()) {
			return null;
		}
		BlockInfo blockInfo = tailMap.get(tailMap.firstKey());
		BigInteger byteIndex = index.multiply(bytesInLine).add(BigInteger.valueOf(fieldOffset));
		if ((byteIndex.compareTo(blockInfo.blockStart) >= 0) &&
			(byteIndex.compareTo(blockInfo.blockEnd) < 0)) {
			return new IndexedByteBlockInfo(index, blockInfo.block,
				byteIndex.subtract(blockInfo.blockStart), 0);
		}
		return null;
	}

	/**
	 * Returns true if the given index is between blocks.
	 * @param index the index to check if it is a block separator index
	 * @return true if the given index is between blocks.
	 */
	boolean isBlockSeparatorIndex(BigInteger index) {
		return blockInfoMap.containsKey(index);
	}

	/**
	 * Returns a field location for the given block, offset.
	 * @param block the ByteBlock containing the byte to get a FieldLocation for
	 * @param offset the byte offset in the block
	 * @param factories that generated values for a line
	 * @return the field location for the given byte location
	 */
	FieldLocation getFieldLocation(ByteBlock block, BigInteger offset, FieldFactory[] factories) {
		for (BlockInfo blockInfo : blockInfoMap.values()) {
			if (blockInfo.block == block) {
				BigInteger byteIndex = blockInfo.blockStart.add(offset);
				BigInteger index = byteIndex.divide(bytesInLine);
				int lineOffset = byteIndex.remainder(bytesInLine).intValue();

				//int fieldOffset = lineOffset / fields.length;
				int nbytesPerField = bytesInLine.intValue() / factories.length;
				int fieldOffset = (lineOffset / nbytesPerField) * nbytesPerField;

				int byteOffset = lineOffset % nbytesPerField;

				int fieldNum = getFieldNum(index, fieldOffset, factories);
				int col = factories[fieldNum].getColumnPosition(block, byteOffset);
				return new FieldLocation(index, fieldNum, 0, col);
			}
		}
		return null;
	}

	/**
	 * Returns the index of the first factory that is active for a given index
	 * @param index the line index
	 * @param factories the list of factories that generate values on a line
	 * @return the index of the first active factory on that line. This will be 0 except for
	 * the first line of a block which may start part way in the line.
	 */
	int getFirstActiveFactoryIndex(BigInteger index, FieldFactory[] factories) {
		for (int i = 0; i < factories.length; i++) {
			if (factories[i].isActive(index)) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Returns the index of the last factory that is active for a given index
	 * @param index the line index
	 * @param factories the list of factories that generate values on a line
	 * @return the index of the last active factory on that line. This will be factories.length
	 * except for the last line of a block which may end part way in the line.
	 */
	int getLastActiveFactoryIndex(BigInteger index, FieldFactory[] factories) {
		for (int i = factories.length - 1; i >= 0; i--) {
			if (factories[i].isActive(index)) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Gets the field offset (byte offset from the beginning of the line) for the given index
	 * and fieldNum.
	 * @param lineIndex the line index to get the field offset. This only matters because some indexes
	 * don't use all the fields and have blanks in some of the factory field locations. Fieldnum
	 * starts counting from the first visible field.
	 * @param fieldNum the index of the field to get an offset for. This is complicated by the
	 * fact that fieldNum is 0 for the first visible field.
	 * @param factories the list of factories that generate byte fields per line. The factories
	 * are identical except for which offset it uses to get its bytes for display.
	 * @return the byte offset from the byte that would be shown at the beginning of the line
	 */
	int getFieldOffset(BigInteger lineIndex, int fieldNum, FieldFactory[] factories) {
		int firstActiveFactoryIndex = getFirstActiveFactoryIndex(lineIndex, factories);
		if (firstActiveFactoryIndex < 0) {
			return 0;
		}
		int lastActiveFactoryIndex = getLastActiveFactoryIndex(lineIndex, factories);
		int factoryIndex = firstActiveFactoryIndex + fieldNum;
		if (factoryIndex <= lastActiveFactoryIndex) {
			return factories[factoryIndex].getFieldOffset();
		}
		return factories[lastActiveFactoryIndex].getFieldOffset();
	}

	/**
	 * Gets field factory index for the given fieldOffset, adjusting for inactive fields such
	 * that the first active field has a fieldNum of 0. For example, if the group size is 2 and
	 * bytes per line is 8,then the factories have fieldOffsets of 0,2,4,6. So if all fields are
	 * visible, the fieldNum for 4 is 2. But if the first field is non active, then the offset of
	 * 4 maps to fieldNum of 1.
	 * @param lineIndex the line index to get a fieldNum for
	 * @param fieldOffset the byte offset from the byte that would be displayed by the first factory
	 * (the first factory always has an offset of 0)
	 * @param factories the list of factories for a line
	 * @return the active index of the factory that displays bytes at the given fieldOffset. 
	 */
	int getFieldNum(BigInteger lineIndex, int fieldOffset, FieldFactory[] factories) {
		int firstActiveFactoryIndex = getFirstActiveFactoryIndex(lineIndex, factories);
		if (firstActiveFactoryIndex < 0) {
			return 0;
		}
		int lastActiveFactoryIndex = getLastActiveFactoryIndex(lineIndex, factories);
		for (int i = firstActiveFactoryIndex; i < lastActiveFactoryIndex; i++) {
			if (factories[i].getFieldOffset() == fieldOffset) {
				return i - firstActiveFactoryIndex;
			}
		}

		return lastActiveFactoryIndex - firstActiveFactoryIndex;
	}

	/**
	 * Returns the BlockSet.
	 * @return the BlockSet that was used to create this index map
	 */
	ByteBlockSet getByteBlockSet() {
		return blockSet;
	}

	public List<ByteBlock> getBlocksBetween(ByteBlockInfo start, ByteBlockInfo end) {
		ByteBlock startBlock = start.getBlock();
		ByteBlock endBlock = end.getBlock();
		List<ByteBlock> byteBlocks = new ArrayList<ByteBlock>();
		Iterator<BlockInfo> iterator = blockInfoMap.values().iterator();
		while (iterator.hasNext()) {
			BlockInfo next = iterator.next();
			if (next.block == startBlock) {
				break;
			}
		}
		while (iterator.hasNext()) {
			BlockInfo next = iterator.next();
			if (next.block == endBlock) {
				return byteBlocks;
			}
			byteBlocks.add(next.block);
		}
		// didn't find the end, so the end must have been before the start, so return empty list
		return List.of();
	}

}

/**
 * Class to hold compute block index information.
 */
class BlockInfo {
	ByteBlock block;
	BigInteger startIndex;
	BigInteger blockStart;
	BigInteger blockEnd;
	BigInteger endIndex;

	BlockInfo(ByteBlock block, BigInteger startIndex, BigInteger blockStart, BigInteger blockEnd,
			BigInteger endIndex) {
		this.block = block;
		this.startIndex = startIndex;
		this.blockStart = blockStart;
		this.blockEnd = blockEnd;
		this.endIndex = endIndex;
	}
}
