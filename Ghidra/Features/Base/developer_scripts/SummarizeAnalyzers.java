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
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.classfinder.ClassSearcher;

public class SummarizeAnalyzers extends GhidraScript {

	private List<AnalyzerData> byteTasks;
	private List<AnalyzerData> functionTasks;
	private List<AnalyzerData> functionModifierTasks;
	private List<AnalyzerData> functionSignatureTasks;
	private List<AnalyzerData> instructionTasks;
	private List<AnalyzerData> dataTasks;

	private static class AnalyzerData implements Comparable<AnalyzerData> {

		private final Analyzer analyzer;
		private final boolean enabled;

		AnalyzerData(Analyzer analyzer, boolean enabled) {
			this.analyzer = analyzer;
			this.enabled = enabled;
		}

		@Override
		public int compareTo(AnalyzerData arg0) {
			return arg0.analyzer.getPriority().priority() - analyzer.getPriority().priority();
		}

		@Override
		public String toString() {
			return (enabled ? " X " : "   ") +
				StringUtilities.pad(Integer.toString(analyzer.getPriority().priority()), ' ',
					4) + "  " + analyzer.getName() + " (" + analyzer.getClass().getSimpleName() +
				")";
		}
	}

	private void initializeAnalyzers() {

		byteTasks = new ArrayList<AnalyzerData>();
		functionTasks = new ArrayList<AnalyzerData>();
		functionModifierTasks = new ArrayList<AnalyzerData>();
		functionSignatureTasks =	 new ArrayList<AnalyzerData>();
		instructionTasks = new ArrayList<AnalyzerData>();
		dataTasks = new ArrayList<AnalyzerData>();

		Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);

		List<Class<? extends Analyzer>> classes = ClassSearcher.getClasses(Analyzer.class);
		for (Class<? extends Analyzer> element : classes) {
			Analyzer analyzer;
			try {
				analyzer = element.newInstance();
			}
			catch (Exception e) {
				Msg.showError(this, null, "Analyzer Error", "Cannot instantiate " + element + "  " +
					e.getMessage(), e);
				continue;
			}
			if (!analyzer.canAnalyze(currentProgram)) {
				continue;
			}

			boolean enabled = options.getBoolean(analyzer.getName(), false);

			AnalyzerType type = analyzer.getAnalysisType();
			if (type == AnalyzerType.BYTE_ANALYZER) {
				byteTasks.add(new AnalyzerData(analyzer, enabled));
			}
			else if (type == AnalyzerType.DATA_ANALYZER) {
				dataTasks.add(new AnalyzerData(analyzer, enabled));
			}
			else if (type == AnalyzerType.FUNCTION_ANALYZER) {
				functionTasks.add(new AnalyzerData(analyzer, enabled));
			}
			else if (type == AnalyzerType.FUNCTION_MODIFIERS_ANALYZER) {
				functionModifierTasks.add(new AnalyzerData(analyzer, enabled));
			}
			else if (type == AnalyzerType.FUNCTION_SIGNATURES_ANALYZER) {
				functionSignatureTasks.add(new AnalyzerData(analyzer, enabled));
			}
			else if (type == AnalyzerType.INSTRUCTION_ANALYZER) {
				instructionTasks.add(new AnalyzerData(analyzer, enabled));
			}
			else {
				Msg.showError(this, null, "Unknown Analysis Type", "Unexpected Analysis type " +
					type);
			}
		}

		Collections.sort(byteTasks);
		Collections.sort(instructionTasks);
		Collections.sort(functionTasks);
		Collections.sort(functionModifierTasks);
		Collections.sort(functionSignatureTasks);
		Collections.sort(dataTasks);
	}

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			return;
		}

		initializeAnalyzers();

		dump("Byte Analyzers", byteTasks);
		dump("Instruction Analyzers", instructionTasks);
		dump("Function Analyzers", functionTasks);
		dump("Function Modifier Analyzers", functionModifierTasks);
		dump("Function Signature Analyzers", functionSignatureTasks);
		dump("Data Analyzers", dataTasks);

	}

	private void dump(String type, List<AnalyzerData> list) {

		println("*** " + type + " ***");

		for (AnalyzerData data : list) {
			println(data.toString());
		}

	}

}
