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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.*;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.program.model.data.DataType;

/**
 * Applier context used for fixups of data types
 */
public class FixupContext {

	private Deque<Integer> stagedRecordFifo = new ArrayDeque<>();
	private Deque<Integer> inProgressRecordStack = new ArrayDeque<>();
	private Deque<Integer> fixupRecordFifo = new ArrayDeque<>();

	private Map<Integer, List<Integer>> map = new HashMap<>();
	private Map<Integer, DataType> fixupTypes = new HashMap<>();

	/**
	 * Checks that record is already being processed and, if not, adds it to the Staged state
	 * @param record the number of the record
	 * @throws PdbException upon the record already in the process or fixup state
	 */
	void ensureInContext(int record) throws PdbException {
		if (inProgressRecordStack.contains(record)) {
			return;
		}
		if (fixupRecordFifo.contains(record)) {
			return;
		}
		addStagedRecord(record);
	}

	DataType getFixupDataType(int record) {
		return fixupTypes.get(record);
	}

	/**
	 * Adds record to the Staged state if not already there
	 * @param recordNumber the number of the record
	 * @throws PdbException upon the record already in the process or fixup state
	 */
	void addStagedRecord(int recordNumber) throws PdbException {
		if (stagedRecordFifo.contains(recordNumber)) {
			return;
		}
		if (inProgressRecordStack.contains(recordNumber)) {
			throw new PdbException("Record Number in process state: " + recordNumber);
		}
		if (fixupRecordFifo.contains(recordNumber)) {
			throw new PdbException("Record Number in fixup state: " + recordNumber);
		}
		if (map.containsKey(recordNumber)) {
			throw new PdbException("Record Number already exists: " + recordNumber);
		}
		map.put(recordNumber, new ArrayList<>());
		putStagedRecord(recordNumber);
	}

	/**
	 * Moves the next record in the Staged state to the process state and returns its number
	 * @return the number of the record moved
	 * @throws PdbException if the record happens to be in another state (should not happen if
	 * in the Staged state)
	 */
	Integer moveFromStagedToProcessRecord() throws PdbException {
		Integer record = getStagedRecord();
		if (record != null) {
			putProcessRecord(record);
		}
		return record;
	}

	/**
	 * Puts the specified record number from the Staged state to the Process state
	 * @param number the number of the record
	 * @throws PdbException if the record is not in the Staged state
	 */
	void moveFromStagedToProcessRecord(int number) throws PdbException {
		if (!stagedRecordFifo.remove(number)) {
			throw new PdbException("Number not in Staged state: " + number);
		}
		putProcessRecord(number);
	}

	/**
	 * Puts the specified record to the head of the Process state.  If the record had been
	 *  in the Staged state or anywhere else in the Process state, it is moved to the head of the
	 *  Process state
	 * @param number the number of the record
	 * @throws PdbException if the records is not in the Staged state
	 */
	void moveToHeadProcessRecord(int number) throws PdbException {
		if (stagedRecordFifo.contains(number)) {
			stagedRecordFifo.remove(number);
		}
		else if (inProgressRecordStack.contains(number)) {
			inProgressRecordStack.remove(number);
			inProgressRecordStack.offerFirst(number);
		}
		else {
			map.put(number, new ArrayList<>());
		}
		putProcessRecord(number);
	}

	/**
	 * Moves the specified record from the Process state to the Fixup state
	 * @param number the number of the record
	 * @param dataType the type that has been created for this in-progress type
	 * @throws PdbException if the record is not in the Process state
	 */
	void moveProcessToFixupsRecord(int number, DataType dataType) throws PdbException {
		if (!inProgressRecordStack.remove(number)) {
			throw new PdbException("Number not in process state: " + number);
		}
		if (fixupTypes.containsKey(number)) {
			throw new PdbException("Number already in progress: " + number);
		}
		putFixupsRecord(number);
		fixupTypes.put(number, dataType);
	}

	/**
	 * Removes the next record from the Fixup state and returns the number
	 * @return the number
	 */
	Integer popFixupsRecord() {
		Integer record = getFixupsRecord();
		if (record != null) {
			if (map.containsKey(record)) {
				map.remove(record);
			}
			if (fixupTypes.containsKey(record)) {
				fixupTypes.remove(record);
			}
		}
		return record;
	}

	// Not sure we will use this method
	/**
	 * Removes the head of the Process state and returns the number.  The number is not moved
	 *  to the Fixup state
	 * @return the number
	 */
	Integer popProcessRecord() {
		Integer record = getProcessRecord();
		if (record != null) {
			if (map.containsKey(record)) {
				map.remove(record);
			}
			// Since pop from current, not adding to fixups
		}
		return record;
	}

	private void putStagedRecord(int record) throws PdbException {
		if (stagedRecordFifo.contains(record)) {
			return;
		}
		if (inProgressRecordStack.contains(record)) {
			throw new PdbException("Record exists in another state: " + record);
		}
		if (fixupRecordFifo.contains(record)) {
			throw new PdbException("Record exists in another state: " + record);
		}
		stagedRecordFifo.addFirst(record);
	}

	private Integer getStagedRecord() {
		return stagedRecordFifo.pollLast();
	}

	/**
	 * Peeks at and returns the record number of the head of the Staged state
	 * @return the record number
	 */
	Integer peekStagedRecord() {
		return stagedRecordFifo.peekLast();
	}

	private void putProcessRecord(int record) throws PdbException {
		if (inProgressRecordStack.contains(record)) {
			return;
		}
		if (stagedRecordFifo.contains(record)) {
			throw new PdbException("Record exists in another state: " + record);
		}
		if (fixupRecordFifo.contains(record)) {
			throw new PdbException("Record exists in another state: " + record);
		}
		inProgressRecordStack.addFirst(record);
	}

	private Integer getProcessRecord() {
		return inProgressRecordStack.pollFirst();
	}

	private void putFixupsRecord(int record) throws PdbException {
		if (fixupRecordFifo.contains(record)) {
			return;
		}
		if (stagedRecordFifo.contains(record)) {
			throw new PdbException("Record exists in another state: " + record);
		}
		if (inProgressRecordStack.contains(record)) {
			throw new PdbException("Record exists in another state: " + record);
		}
		fixupRecordFifo.addFirst(record);
	}

	/**
	 * Peeks at and returns the record number of the head of the Process state
	 * @return the record number
	 */
	Integer peekProcessRecord() {
		return inProgressRecordStack.peekFirst();
	}

	/**
	 * Removes and returns the record number of the head of the Fixup state
	 * @return the record number
	 */
	Integer getFixupsRecord() {
		return fixupRecordFifo.pollLast();
	}

	/**
	 * Peeks at and returns the record number of the head of the Fixup state
	 * @return the record number
	 */
	Integer peekFixupsRecord() {
		return fixupRecordFifo.peekLast();
	}

	//==============================================================================================

	/**
	 * Puts the fixup index into the fixups for the current head of the Process state
	 * @param fixupIndex the fixup index
	 * @throws PdbException if the head of the Process state is empty or is fixups cannot be found
	 */
	void putFixup(int fixupIndex) throws PdbException {
		List<Integer> fixups = getProcessFixups();
		fixups.add(fixupIndex);
	}

	/**
	 * Returns true if the fixups for the current head of the Process state is empty
	 * @return {@code true} if empty
	 * @throws PdbException if there is no head of the Process state or its fixups cannot be found
	 */
	boolean processFixupsIsEmpty() throws PdbException {
		List<Integer> fixups = getProcessFixups();
		return fixups.isEmpty();
	}

	/**
	 * Peeks at and returns head of the Fixup state
	 * @return the number of the record
	 */
	Integer peekFixupRecord() {
		return peekFixupsRecord();
	}

	/**
	 * Returns the fixups for the head of the Fixups state
	 * @return the fixup indices
	 * @throws PdbException if the head of the Fixups state does not exist or its fixups cannot be
	 *  found
	 */
	List<Integer> getFixups() throws PdbException {
		Integer record = peekFixupsRecord();
		if (record == null) {
			throw new PdbException("Empty fixups retrieval");
		}
		List<Integer> fixups = map.get(record);
		if (fixups == null) {
			throw new PdbException("Fixups not found on retrieval");
		}
		return fixups;
	}

	private List<Integer> getProcessFixups() throws PdbException {
		Integer record = peekProcessRecord();
		if (record == null) {
			throw new PdbException("Context empty on fixups retrieval");
		}
		List<Integer> fixups = map.get(record);
		if (fixups == null) {
			throw new PdbException("Fixups not found");
		}
		return fixups;
	}

}
