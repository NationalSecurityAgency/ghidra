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
package ghidra.framework.analysis;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.Analyzer;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;

public class AnalysisRecipeBuilder {

	private static List<Class<? extends Analyzer>> classes;

	public static AnalysisRecipe getRecipe(Program program) {

		AnalysisRecipe recipe = findRecipe(program);

		if (recipe == null) {
			recipe = buildDefaultRecipe(program);
		}

		return recipe;
	}

	private static AnalysisRecipe buildDefaultRecipe(Program program) {
		List<Analyzer> analyzerList = new ArrayList<Analyzer>();
		List<Analyzer> anayzers = ClassSearcher.getInstances(Analyzer.class);
		for (Analyzer analyzer : anayzers) {
			if (analyzer.canAnalyze(program)) {
				analyzerList.add(analyzer);
			}
		}
		return new AnalysisRecipe("Default", analyzerList, program);

	}

	private static AnalysisRecipe findRecipe(Program program) {
		return new AnalysisRecipe("Default", ClassSearcher.getInstances(Analyzer.class), program);
	}

}
