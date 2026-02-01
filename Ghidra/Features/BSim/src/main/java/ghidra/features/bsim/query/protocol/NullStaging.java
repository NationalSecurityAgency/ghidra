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
package ghidra.features.bsim.query.protocol;

import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.DescriptionManager;

public class NullStaging extends StagingManager {

	@Override
	public BSimQuery<?> getQuery() {
		return globalQuery;
	}

	@Override
	public boolean initialize(BSimQuery<?> q) throws LSHException {
		globalQuery = q;
		totalsize = 0;
		queriesmade = 0;
		
		DescriptionManager imanage = q.getDescriptionManager();
		if (imanage == null)
			return true;

		totalsize = imanage.numFunctions();
		return (totalsize != 0);	// Is there any data at all for an initial stage
	}

	@Override
	public boolean nextStage() {
		queriesmade = totalsize;
		return false;		// There is always only one stage
	}
}
