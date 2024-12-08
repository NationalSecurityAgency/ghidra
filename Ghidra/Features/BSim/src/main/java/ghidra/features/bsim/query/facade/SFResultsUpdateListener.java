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
package ghidra.features.bsim.query.facade;

import ghidra.features.bsim.query.protocol.QueryResponseRecord;

/**
 * A listener that will be called as incremental results arrive from database queries.  
 * The results given to this listener are always a subset of the complete results.
 * @param <R> the final result implementation class.
 */
public interface SFResultsUpdateListener<R> {

//	/**
//	 * Status callback
//	 * @param message status message
//	 * @param type message type
//	 */
//	void updateStatus(String message, MessageType type);
//
	/**
	 * Called as incremental results arrive from database queries.  The results given to
	 * this listener are always a subset of the complete results--they are not comprehensive.
	 * Consumer should be able to safely cast response based upon the type of query being performed.
	 * 	
	 * @param partialResponse a partial result record with the recently received results.
	 */
	public void resultAdded(QueryResponseRecord partialResponse);

	/**
	 * Callback to supply the final accumulated result.
	 * @param result accumulated query result or null if a failure occured which prevented
	 * results from being returned.
	 */
	public void setFinalResult(R result);
}
