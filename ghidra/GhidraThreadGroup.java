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
package ghidra;

import db.TerminatedTransactionException;
import ghidra.framework.model.DomainObjectException;
import ghidra.framework.model.DomainObjectLockedException;
import ghidra.util.Msg;

/**
 * <code>GhidraThreadGroup</code> provides a means of catching all uncaught
 * exceptions which occur in any Ghidra thread.
 */
public class GhidraThreadGroup extends ThreadGroup {

	/**
	 * Constructor for GhidraThreadGroup.
	 */
	public GhidraThreadGroup() {
		super(Thread.currentThread().getThreadGroup(), "Ghidra");
	}

	@Override
	public void uncaughtException(Thread t, Throwable e) {
		handleUncaughtException(e);
	}

	/**
	 * Handle any uncaught throwable/exception.
	 * @param t throwable
	 */
	public static void handleUncaughtException(Throwable t) {
		if (t instanceof DomainObjectException) {
			t = t.getCause();
		}
		if (t instanceof TerminatedTransactionException) {
			Msg.showError(
				GhidraThreadGroup.class,
				null,
				"Terminated Transaction",
				"Transaction has been terminated!\n \n"
					+ "All open transactions must be closed before a new transaction will be allowed.\n"
					+ "Try cancelling all long running tasks.\n \n"
					+ "Note that this error may be repeated until all running tasks are terminated.");
			return;
		}

		if (t instanceof DomainObjectLockedException) {
			Msg.showError(GhidraThreadGroup.class, null, "Transaction Not Allowed", t.getMessage() +
				"\n \n" + "No modifications are permitted until the locking process has completed.");
			return;
		}

		// pass up for more generic exception handling
		SwingExceptionHandler.handleUncaughtException(t);
	}

}
