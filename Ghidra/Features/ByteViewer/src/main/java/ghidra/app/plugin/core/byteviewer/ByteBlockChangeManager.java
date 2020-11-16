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

import ghidra.app.plugin.core.format.ByteBlock;
import ghidra.app.plugin.core.format.ByteEditInfo;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;

/**
 * Helper class to manage changes within byte blocks; determines what offsets
 * have changed so the changes can be rendered properly in the Byte Viewer.
 */
class ByteBlockChangeManager {

	private ProgramByteBlockSet blockSet;
	private List<ByteEditInfo> changeList; // list of changes for this tool

	private final static String NUMBER_OF_CHANGES = "NumberOfByteBlockChanges";
	private static String BLOCK_NUMBER = "BlockNumber";
	private static String BLOCK_OFFSET = "BlockOffset";
	private static String OLD_VALUE = "OldValue";
	private static String NEW_VALUE = "NewValue";

	private int dummy = 4;

	/**
	 * Construct new change manager.
	 */
	ByteBlockChangeManager(ProgramByteBlockSet blockSet) {
		this.blockSet = blockSet;
		changeList = new ArrayList<ByteEditInfo>(3);
	}

	ByteBlockChangeManager(ProgramByteBlockSet blockSet, ByteBlockChangeManager bbcm) {

		this.blockSet = blockSet;
		changeList = bbcm.changeList;
	}

	/**
	 * Add a change to the change list.
	 * @param edit edit object that has the old value and new value
	 * 
	 */
	void add(ByteEditInfo edit) {
		byte[] oldValue = edit.getOldValue();
		byte[] newValue = edit.getNewValue();

		Address blockAddr = edit.getBlockAddress();
		BigInteger offset = edit.getOffset();
		for (int i = 0; i < oldValue.length; i++) {
			if (oldValue[i] == newValue[i]) {
				continue;
			}
			ByteEditInfo newedit = new ByteEditInfo(blockAddr, offset.add(BigInteger.valueOf(i)),
				oldValue, newValue);
			changeList.add(newedit);
		}
	}

	/**
	 * Write the state of the change list.
	 */
	SaveState getUndoRedoState() {
		SaveState saveState = new SaveState();
		int changeCount = changeList.size();
		for (int i = 0; i < changeList.size(); i++) {
			ByteEditInfo edit = changeList.get(i);
			int blockNumber = blockSet.getByteBlockNumber(edit.getBlockAddress());
			if (blockNumber >= 0) {
				++changeCount;
				saveState.putInt(BLOCK_NUMBER + i, blockNumber);
				saveState.putString(BLOCK_OFFSET + i, edit.getOffset().toString());
				saveState.putBytes(OLD_VALUE + i, edit.getOldValue());
				saveState.putBytes(NEW_VALUE + i, edit.getNewValue());
			}
		}
		saveState.putInt(NUMBER_OF_CHANGES, changeCount);
		return saveState;
	}

	/**
	 * Read the state of the change list.
	 */
	void restoreUndoRedoState(SaveState saveState) {
		changeList.clear();
		int numberOfChanges = saveState.getInt(NUMBER_OF_CHANGES, 0);
		for (int i = 0; i < numberOfChanges; i++) {
			int blockNumber = saveState.getInt(BLOCK_NUMBER + i, 0);
			BigInteger blockOffset = new BigInteger(saveState.getString(BLOCK_OFFSET + i, "0"));
			byte[] oldValue = saveState.getBytes(OLD_VALUE + i, null);
			byte[] newValue = saveState.getBytes(NEW_VALUE + i, null);

			if (oldValue != null && newValue != null) {
				changeList.add(new ByteEditInfo(blockSet.getBlockStart(blockNumber), blockOffset,
					oldValue, newValue));
			}
		}
	}

	/**
	 * Return true if any offset in the range offset to offset+unitByteSize-1
	 * is in either of the change lists.
	 * @param block block in question
	 * @param offset offset into the block
	 * @param unitByteSize number of bytes in the unit (dictated by the
	 * data format model)
	 * 
	 * @return boolean true if an offset in the range was found
	 */
	boolean isChanged(ByteBlock block, BigInteger offset, int unitByteSize) {
		Address blockAddr = blockSet.getBlockStart(block);
		for (int i = 0; i < unitByteSize; i++) {

			if (contains(blockAddr, offset.add(BigInteger.valueOf(i)))) {
				return true;
			}
		}
		return false;
	}

	//////////////////////////////////////////////////////////////////////
	/**
	 * Return true if the block and offset are in the list.
	 * @param list either the local change list or the external change list
	 * @param block block in question
	 * @param offset offset into the block
	 */
	private boolean contains(Address blockAddr, BigInteger offset) {
		for (int i = 0; i < changeList.size(); i++) {
			ByteEditInfo edit = changeList.get(i);
			if (edit.getBlockAddress().compareTo(blockAddr) == 0 &&
				edit.getOffset().equals(offset)) {
				return true;
			}
		}
		return false;
	}
}
