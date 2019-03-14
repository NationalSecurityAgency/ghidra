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
package ghidra.framework.data;

import ghidra.util.exception.CancelledException;

/**
 * <code>CheckinHandler</code> facilitates application callbacks during
 * the check-in of a DomainFile.
 */
public interface CheckinHandler {
	/**
	 * Returns the check-in comment.
	 * @return the check-in comment
	 * @throws CancelledException thrown if user cancels the check-in
	 */
	String getComment() throws CancelledException;
	/**
	 * Returns true if check-out state should be retained.
	 * @return true if check-out state should be retained
	 * @throws CancelledException thrown if user cancels the check-in
	 */
	boolean keepCheckedOut() throws CancelledException;
	
	/**
	 * Returns true if the system should create a keep file copy of the user's check-in file.
	 * @throws CancelledException thrown if user cancels the check-in
	 */
	boolean createKeepFile() throws CancelledException; 

}
