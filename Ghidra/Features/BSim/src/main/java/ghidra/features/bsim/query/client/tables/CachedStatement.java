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
package ghidra.features.bsim.query.client.tables;

import java.sql.SQLException;
import java.sql.Statement;

import ghidra.util.Msg;

/**
 * {@link CachedStatement} provides a cached {@link Statement} container which is intended to
 * supply a reusable instance for use within a single thread.  Attempts to use the statement
 * in multiple threads is considered unsafe.
 *
 * @param <S> {@link Statement} implementation class
 */
public class CachedStatement<S extends Statement> {

	private S statement;
	private Thread ownerThread;

	/**
	 * Get the associated cached {@link Statement} or prepare one via the specified 
	 * {@code statementSupplier} if not yet established.  Tf the supplier is used
	 * the owner thread for the statement will be established based on the 
	 * {@link Thread#currentThread()}.
	 * 
	 * @param statementSupplier statement supplier function which must return a valid
	 * instance or throw an exception.
	 * @return statement
	 * @throws SQLException if supplier fails to produce a statement
	 * @throws RuntimeException if the current thread does not correspond to the owner
	 * thread of a previously established statement.  This is considered a programming
	 * error if this occurs.
	 */
	public S prepareIfNeeded(StatementSupplier<S> statementSupplier) throws SQLException {
		S s = getStatement();
		if (s != null) {
			return s;
		}
		s = statementSupplier.get();
		setStatement(s);
		return s;
	}

	/**
	 * Set the associated {@link Statement} instance.  This method may be used in place of
	 * {@link #prepareIfNeeded(StatementSupplier)} although it is not preferred since it
	 * can result in replacement of one previously established.  The {@link #getStatement()}
	 * should be used first to ensure one was not previously set.  An error will be logged
	 * if the invocation replaces an existing statement which will be forced closed.
	 * <B>
	 * The owner thread for the statement will be established based on the 
	 * {@link Thread#currentThread()}.
	 * 
	 * @param s statement to be cached
	 */
	public void setStatement(S s) {
		S oldStatement = statement;
		statement = s;
		ownerThread = Thread.currentThread();
		if (oldStatement != null) {
			Msg.error(this, "Statement cached more than once - closing old statement");
			try {
				oldStatement.close();
			}
			catch (SQLException e) {
				// ignore
			}
		}
	}

	/**
	 * Get the current cached {@link Statement}.
	 * 
	 * @return the current cached {@link Statement} or null if not yet established.
	 * @throws RuntimeException if the current thread does not correspond to the owner
	 * thread of a previously established statement.  This is considered a programming
	 * error if this occurs.
	 */
	public S getStatement() {
		Thread t = Thread.currentThread();
		if (statement != null && !ownerThread.equals(t)) {
			Msg.error(this, "BSim cached statement used in unsafe-thread manner:" +
				"\n   Created in: " + ownerThread.getName() + "\n   Used in: " + t.getName());
			throw new RuntimeException("BSim cached statement used in unsafe-thread manner");
		}
		return statement;
	}

	/**
	 * Close the currently cached {@link Statement}.  This method may be invoked
	 * from any thread but should be properly coordinated with its use in the statement
	 * owner thread.
	 */
	public void close() {
		if (statement != null) {
			try {
				statement.close();
			}
			catch (SQLException e) {
				// ignore
			}
			statement = null;
		}
	}

}
