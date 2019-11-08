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
package ghidra.framework.main;

/**
 * This class helps implement a workaround to deal with a UI lockup issue.  Clients performing
 * long-running version control actions that require a lock have the potential to block 
 * the UI thread when the action context is updated.  This is because some actions will check
 * their enablement by examining file version control state, which requires a lock.   The enablement
 * check happens in the Swing thread.  Thus, when the required lock is already in use for a 
 * long-running operation, the UI is blocked.   This class effectively provides a global state
 * flag that can be maintained by the the owner of the aforementioned actions.   When a check
 * for action enablement happens, if this flag is marked 'busy', then the enablement check
 * will not take place. 
 */
public class DomainFileOperationTracker {

	private volatile boolean isBusy;

	public void setBusy(boolean isBusy) {
		this.isBusy = isBusy;
	}

	public boolean isBusy() {
		return isBusy;
	}
}
