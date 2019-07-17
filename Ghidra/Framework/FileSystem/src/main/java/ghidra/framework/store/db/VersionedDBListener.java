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
package ghidra.framework.store.db;

import java.io.IOException;

/**
 * <code>VersionedDBListener</code> provides listeners the ability to be notified
 * when changes occur to a versioned database.
 */
public interface VersionedDBListener {

	/**
	 * Available database versions have been modified.
	 * This method is not invoked when a new version is created.
	 * @param minVersion minimum available version
	 * @param currentVersion current/latest version
	 */
	public void versionsChanged(int minVersion, int currentVersion);

	/**
	 * A new database version has been created.
	 * @param db
	 * @param version
	 * @param time
	 * @param comment
	 * @param checkinId
	 * @return true if version is allowed, if false is returned 
	 * the version will be removed.
	 */
	public boolean versionCreated(VersionedDatabase db, int version, long time, String comment,
			long checkinId);

	/**
	 * A version has been deleted.
	 * @param version
	 */
	public void versionDeleted(int version);

	/**
	 * Returns the checkout version associated with the specified
	 * checkoutId.  A returned version of -1 indicates that the 
	 * checkoutId is not valid.
	 * @param checkoutId
	 * @return checkout version
	 */
	public int getCheckoutVersion(long checkoutId) throws IOException;

	/**
	 * Terminate the specified checkout.
	 * A new version may or may not have been created.
	 * @param checkoutId
	 */
	public void checkinCompleted(long checkoutId);

}
