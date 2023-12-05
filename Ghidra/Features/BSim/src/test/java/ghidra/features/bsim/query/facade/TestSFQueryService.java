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

import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.protocol.ResponseNearestVector;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class TestSFQueryService extends SimilarFunctionQueryService {

	private FunctionDatabase testDatabase;

	public TestSFQueryService(Program program, FunctionDatabase database) {
		super(program, database);
		this.testDatabase = database;
	}

	@Override
	public void initializeDatabase(String serverURLString) throws QueryDatabaseException {
		return;
	}

	@Override
	public ResponseNearestVector overviewSimilarFunctions(SFOverviewInfo overviewInfo,
			SFResultsUpdateListener<ResponseNearestVector> listener, TaskMonitor monitor)
			throws QueryDatabaseException, CancelledException {

		ResponseNearestVector response = (ResponseNearestVector) testDatabase.query(null);
		listener.setFinalResult(response);
		return response;
	}

}
