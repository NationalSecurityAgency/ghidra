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
package ghidra.app.plugin.core.byteviewer;

import ghidra.app.plugin.core.format.*;

import java.math.BigInteger;
import java.util.*;

import docking.widgets.fieldpanel.support.FieldLocation;

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
				remainder == 0 ? blockEnd : blockEnd.add(BigInteger.valueOf(bytesPerLine -
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
	 */
	BigInteger getNumIndexes() {
		return numIndexes;
	}

	/**
	 * Returns the number of bytes per line.
	 */
	int getBytesPerLine() {
		return bytesInLine.intValue();
	}

	/**
	 * Returns block location information about the given index and fieldOffset.
	 */
	ByteBlockInfo getBlockInfo(BigInteger index, int fieldOffset) {
		SortedMap<BigInteger, BlockInfo> tailMap = blockInfoMap.tailMap(index);
		if (tailMap.isEmpty()) {
			return null;
		}
		BlockInfo blockInfo = tailMap.get(tailMap.firstKey());
		BigInteger byteIndex = index.multiply(bytesInLine).add(BigInteger.valueOf(fieldOffset));
		if ((byteIndex.compareTo(blockInfo.blockStart) >= 0) &&
			(byteIndex.compareTo(blockInfo.blockEnd) < 0)) {
			return new ByteBlockInfo(blockInfo.block, byteIndex.subtract(blockInfo.blockStart));
		}
		return null;
	}

	/**
	 * Returns true if the given index is between blocks.
	 */
	boolean showSeparator(BigInteger index) {
		return blockInfoMap.containsKey(index);
	}

	/**
	 * Returns a field location for the given block, offset.
	 */
	FieldLocation getFieldLocation(ByteBlock block, BigInteger offset, FieldFactory[] factorys) {
		for (BlockInfo blockInfo : blockInfoMap.values()) {
			if (blockInfo.block == block) {
				BigInteger byteIndex = blockInfo.blockStart.add(offset);
				BigInteger index = byteIndex.divide(bytesInLine);
				int lineOffset = byteIndex.remainder(bytesInLine).intValue();

				//int fieldOffset = lineOffset / fields.length;
				int nbytesPerField = bytesInLine.intValue() / factorys.length;
				int fieldOffset = (lineOffset / nbytesPerField) * nbytesPerField;

				int byteOffset = lineOffset % nbytesPerField;

				int fieldNum = getFieldNum(index, fieldOffset, factorys);
				int col = factorys[fieldNum].getColumnPosition(block, byteOffset);
				return new FieldLocation(index, fieldNum, 0, col);
			}
		}
		return null;
	}

	int getFieldOffset(BigInteger index, int fieldNum, FieldFactory[] factorys) {
		int numFields = 0;
		for (int i = 0; i < factorys.length; i++) {
			ByteField bf = (ByteField) factorys[i].getField(index);
			if (bf != null) {
				if (numFields == fieldNum) {
					return factorys[i].getFieldOffset();
				}
				numFields++;
			}
		}
		return (numFields > 0) ? factorys[numFields - 1].getFieldOffset() : 0;
	}

	int getFieldNum(BigInteger index, int fieldOffset, FieldFactory[] factorys) {
		int fieldNum = 0;
		for (int j = 0; j < factorys.length; j++) {
			ByteField bf = (ByteField) factorys[j].getField(index);
			if (bf != null) {
				if (bf.getFieldOffset() == fieldOffset) {
					break;
				}
				fieldNum++;
			}
		}
		if (fieldNum >= factorys.length) {
			fieldNum = 0;
		}
		return fieldNum;
	}

	/**
	 * Returns the BlockSet.
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
				break;
			}
			byteBlocks.add(next.block);
		}
		return byteBlocks;

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
