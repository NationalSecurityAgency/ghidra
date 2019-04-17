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
package db;

/**
 * <code>TerminatedTransactionException</code> occurs when a database modification is
 * attempted following the forced/premature termination of an open transaction.
 */
public class TerminatedTransactionException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	/**
	 * Constructor.
	 */
	public TerminatedTransactionException() {
		super("Transaction has been terminated");
	}
}
