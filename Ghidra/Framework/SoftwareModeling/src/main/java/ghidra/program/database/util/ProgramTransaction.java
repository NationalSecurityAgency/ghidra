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
package ghidra.program.database.util;

import ghidra.program.model.listing.Program;

/**
 * A convenience context for transaction IDs on a Ghidra program database
 * 
 * <p>
 * This is meant to be used as an idiom in a try-with-resources block:
 * 
 * <pre>
 * try (ProgramTransaction t = ProgramTransaction.open(program, "Demo")) {
 *     program.getMemory().....
 *     t.commit();
 * }
 * </pre>
 * 
 * <p>
 * This idiom is very useful if there is complex logic in your transaction, it's very easy to forget
 * to close the transaction, especially if an error occurs, leaving the database in an open
 * transaction indefinitely. The try-with-resources block will ensure that the transaction is closed
 * in all circumstances. Note, however, that in order for the transaction to be committed, you must
 * call {@link #commit()}.
 * 
 * <p>
 * Any exceptions within the block will cause {@code t.commit()} to be skipped, thus aborting the
 * transaction.
 */
public class ProgramTransaction implements AutoCloseable {
	protected Program program;
	protected int tid;
	protected boolean commit = false;

	/**
	 * Start a transaction on the given program with the given description
	 * 
	 * @param program the program to modify
	 * @param description a description of the transaction
	 */
	public static ProgramTransaction open(Program program, String description) {
		int tid = program.startTransaction(description);
		return new ProgramTransaction(program, tid);
	}

	private ProgramTransaction(Program program, int tid) {
		this.program = program;
		this.tid = tid;
	}

	/**
	 * Finish the transaction
	 * 
	 * <p>
	 * If this is called before {@link #commit()}, then the transaction is aborted. This is called
	 * automatically at the close of a try-with-resources block.
	 */
	@Override
	public void close() {
		program.endTransaction(tid, commit);
	}

	/**
	 * Finish the transaction, and commit
	 * 
	 * <p>
	 * This MUST be called in order to commit the transaction. The transaction is not committed
	 * until the close of the try-with-resources block.
	 */
	public void commit() {
		commit = true;
	}
}
