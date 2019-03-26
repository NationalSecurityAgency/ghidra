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
package ghidra.app.services;

/**
 * Listener that is notified when the GOTO completes.
 *  
 * 
 */
public interface GoToServiceListener {

	/**
	 * Notification that the GOTO completed.
	 * @param queryString original query string
	 * @param foundResults true if at least one hit was found for the query
	 */
	public void gotoCompleted(String queryString, boolean foundResults);

	/**
	 * Notification that the GOTO failed with an exception.
	 * @param exc the exception that occurred.
	 */
	public void gotoFailed(Exception exc);
}
