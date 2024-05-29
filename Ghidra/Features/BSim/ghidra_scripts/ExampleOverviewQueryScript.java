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
//Example of how to perform an overview query in a script.
//@category BSim
import java.util.HashSet;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.facade.SFOverviewInfo;
import ghidra.features.bsim.query.facade.SimilarFunctionQueryService;
import ghidra.features.bsim.query.protocol.ResponseNearestVector;
import ghidra.features.bsim.query.protocol.SimilarityVectorResult;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.listing.*;

public class ExampleOverviewQueryScript extends GhidraScript {
	private static final double SIMILARITY_BOUND = 0.7;
	private static final double SIGNIFICANCE_BOUND = 0.0;

	@Override
	protected void run() throws Exception {
		Program queryingProgram = currentProgram;
		HashSet<FunctionSymbol> funcsToQuery = new HashSet<>();
		FunctionIterator fIter = queryingProgram.getFunctionManager().getFunctionsNoStubs(true);
		for (Function func : fIter) {
			funcsToQuery.add((FunctionSymbol) func.getSymbol());
		}
		SFOverviewInfo overviewInfo = new SFOverviewInfo(funcsToQuery);
		overviewInfo.setSimilarityThreshold(SIMILARITY_BOUND);
		overviewInfo.setSignificanceThreshold(SIGNIFICANCE_BOUND);

		try (SimilarFunctionQueryService queryService =
			new SimilarFunctionQueryService(queryingProgram)) {
			String DATABASE_URL = askString("Enter database URL", "URL:");
			queryService.initializeDatabase(DATABASE_URL);
			LSHVectorFactory vectorFactory = queryService.getLSHVectorFactory();

			ResponseNearestVector overviewResults =
				queryService.overviewSimilarFunctions(overviewInfo, null, monitor);
			StringBuilder buf = new StringBuilder();
			buf.append("\n");
			for (SimilarityVectorResult result : overviewResults.result) {
				buf.append("Name: ").append(result.getBase().getFunctionName()).append("\n");
				buf.append("Hit Count:  ").append(result.getTotalCount()).append("\n");
				buf.append("Self-significance:  ");
				buf.append(vectorFactory
						.getSelfSignificance(result.getBase().getSignatureRecord().getLSHVector()));
				buf.append("\n\n");
			}
			printf("%s\n", buf.toString());
		}
	}
}
