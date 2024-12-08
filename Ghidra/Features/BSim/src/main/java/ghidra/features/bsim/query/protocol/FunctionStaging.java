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

import java.util.Iterator;

import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.FunctionDescription;

public class FunctionStaging extends StagingManager {
	private BSimQuery<?> localQuery;
	private int stagesize;			// Number of functions per stage
	private Iterator<FunctionDescription> curiter;
	private DescriptionManager gmanage;		// The global function manager
	private DescriptionManager imanage;		// The internal function manager

	public FunctionStaging(int stagesize) {
		this.stagesize = stagesize;
		localQuery = null;
	}

	@Override
	public BSimQuery<?> getQuery() {
		return localQuery;
	}

	@Override
	public boolean initialize(BSimQuery<?> q) throws LSHException {
		globalQuery = q;
		gmanage = q.getDescriptionManager();
		if (gmanage == null)
			throw new LSHException("Query cannot be function staged");
		totalsize = gmanage.numFunctions();
		queriesmade = 0;
		localQuery = q.getLocalStagingCopy();
		imanage = localQuery.getDescriptionManager();

		curiter = gmanage.listAllFunctions();
		imanage.clear();
		imanage.transferSettings(gmanage);
		int count;
		for (count = 0; count < stagesize; ++count) {
			if (!curiter.hasNext())
				break;
			imanage.transferFunction(curiter.next(), true);	// Copy the next function into manager for this stage
			queriesmade += 1;
		}
		return (count != 0);
	}

	@Override
	public boolean nextStage() throws LSHException {
		imanage.clear();
		imanage.transferSettings(gmanage);
		int count;
		for (count = 0; count < stagesize; ++count) {
			if (!curiter.hasNext())
				break;
			imanage.transferFunction(curiter.next(), true);
			queriesmade += 1;
		}
		return (count != 0);
	}
}
