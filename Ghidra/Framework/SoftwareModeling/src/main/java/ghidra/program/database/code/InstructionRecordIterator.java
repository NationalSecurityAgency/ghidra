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
package ghidra.program.database.code;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.io.IOException;
import java.util.Iterator;

import db.DBRecord;
import db.RecordIterator;

/**
 * Converts a record iterator into an instruction iterator.
 */

public class InstructionRecordIterator implements InstructionIterator {
	private CodeManager codeMgr;
	private RecordIterator it;
	private Instruction nextInstruction;
	private boolean forward;

	/**
	 * Constructs a new InstructionRecordIterator
	 * @param codeMgr the code manager
	 * @param it the record iterator.
	 * @param forward the direction of the iterator.
	 */
	public InstructionRecordIterator(CodeManager codeMgr, RecordIterator it, boolean forward) {
		this.codeMgr = codeMgr;
		this.it = it;
		this.forward = forward;
	}

	/**
	 * @see ghidra.program.model.listing.CodeUnitIterator#hasNext()
	 */
	@Override
	public boolean hasNext() {
		if (nextInstruction == null) {
			findNext();
		}
		return nextInstruction != null;
	}

	/**
	 * @see ghidra.program.model.listing.CodeUnitIterator#next()
	 */
	@Override
	public Instruction next() {
		if (hasNext()) {
			Instruction ret = nextInstruction;
			nextInstruction = null;
			return ret;
		}
		return null;
	}

	private void findNext() {
		try {
			while (nextInstruction == null && (forward ? it.hasNext() : it.hasPrevious())) {
				DBRecord record = forward ? it.next() : it.previous();
				nextInstruction = codeMgr.getInstructionDB(record);
			}
		}
		catch (IOException e) {
		}
	}

	/**
	 * @see java.util.Iterator#remove()
	 */
	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<Instruction> iterator() {
		return this;
	}

}
