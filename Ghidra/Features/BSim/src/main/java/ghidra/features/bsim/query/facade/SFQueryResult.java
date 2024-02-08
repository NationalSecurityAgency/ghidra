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

import java.util.List;

import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.features.bsim.query.protocol.SimilarityResult;

/**
 * The result of a call to {@link SimilarFunctionQueryService#querySimilarFunctions(SFQueryInfo, SFResultsUpdateListener, ghidra.util.task.TaskMonitor)}
 */
public class SFQueryResult {

	private final SFQueryInfo info;
	private List<SimilarityResult> resultlist;
	private final DatabaseInfo facadeDatabaseInfo;

	SFQueryResult(SFQueryInfo info, String serverURL, DatabaseInformation databaseInformation,
		ResponseNearest response) {
		this.info = info;
		this.resultlist = response.result;
		this.facadeDatabaseInfo = new DatabaseInfo(serverURL, databaseInformation);
	}

	/**
	 * The original query used to get the results represented by this object.
	 * @return the original query used to get the results represented by this object.
	 */
	public SFQueryInfo getQuery() {
		return info;
	}

	/**
	 * Returns the function database information representing the database server.
	 * @return the function database information representing the database server.
	 */
	public DatabaseInfo getDatabaseInfo() {
		return facadeDatabaseInfo;
	}

	public List<SimilarityResult> getSimilarityResults() {
		return resultlist;
	}
}
