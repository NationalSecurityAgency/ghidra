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
package ghidra.app.plugin.core.decompiler.validator;

import java.util.*;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.conditiontestpanel.ConditionResult;
import docking.widgets.conditiontestpanel.ConditionStatus;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.plugin.core.analysis.validator.PostAnalysisValidator;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpec.EvaluationModelType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class DecompilerValidator extends PostAnalysisValidator {
	private static final String NAME = "Decompiler Validator";

	public DecompilerValidator(Program program) {
		super(program);
	}

	@Override
	public ConditionResult doRun(final TaskMonitor monitor) {

		Listing listing = program.getListing();
		FunctionIterator iter = listing.getFunctions(program.getMemory(), true);
		List<Function> functions = filterFunctions(program, iter, monitor);

		DecompilerCallback<String> callback =
			new DecompilerCallback<>(program, new DecompilerValidatorConfigurer()) {

				@Override
				public String process(DecompileResults results, TaskMonitor m) throws Exception {

					Function f = results.getFunction();
					String errorMessage = results.getErrorMessage();
					if (!StringUtils.isBlank(errorMessage)) {
						return f.getName() + " (" + f.getEntryPoint() + "): " + errorMessage;
					}
					return null;
				}
			};

		try {
			List<String> results =
				ParallelDecompiler.decompileFunctions(callback, functions, monitor);
			return processResults(results);
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception validating functions", e);
		}
		finally {
			callback.dispose();
		}

		return new ConditionResult(ConditionStatus.Error, "Unable to validate functions (see log)");
	}

	private List<Function> filterFunctions(Program p, FunctionIterator iter, TaskMonitor monitor) {

		List<Function> results = new ArrayList<>();
		Listing listing = p.getListing();
		while (iter.hasNext()) {
			Function f = iter.next();

			if (monitor.isCancelled()) {
				return Collections.emptyList();
			}

			Address entryPoint = f.getEntryPoint();
			CodeUnit codeUnitAt = listing.getCodeUnitAt(entryPoint);
			if (codeUnitAt == null) {
				continue;
			}

			if (codeUnitAt instanceof Instruction) {
				results.add(f);
			}
		}
		return results;
	}

	private ConditionResult processResults(Collection<String> results) {
		ConditionStatus status = ConditionStatus.Passed;
		StringBuilder warnings = new StringBuilder();
		for (String errorMessage : results) {
			if (errorMessage == null) {
				continue;
			}

			status = ConditionStatus.Warning;
			warnings.append(errorMessage);
			warnings.append("\n");
		}

		return new ConditionResult(status, warnings.toString());
	}

	@Override
	public String getDescription() {
		return "make sure all the defined functions decompile without exception";
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public String toString() {
		return getName();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class DecompilerValidatorConfigurer implements DecompileConfigurer {

		DecompileOptions options = getDecompilerOptions();

		@Override
		public void configure(DecompInterface decompiler) {
			decompiler.setOptions(options);
			decompiler.openProgram(program);
		}

		private DecompileOptions getDecompilerOptions() {
			try {
				CompilerSpec spec = program.getCompilerSpec();
				PrototypeModel model =
					spec.getPrototypeEvaluationModel(EvaluationModelType.EVAL_CURRENT);
				options.setProtoEvalModel(model.getName());
			}
			catch (Exception e) {
				Msg.warn(this, "problem setting prototype evaluation model: " + e.getMessage());
			}
			return options;
		}

	}
}
