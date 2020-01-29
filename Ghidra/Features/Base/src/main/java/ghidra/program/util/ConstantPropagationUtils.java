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
package ghidra.program.util;

import java.lang.reflect.Field;
import java.util.List;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A class to hold utility methods for working with constant propagation.
 */
public class ConstantPropagationUtils {

	private ConstantPropagationUtils() {
		// static utils class
	}

	/**
	 * Gets the appropriate {@link ConstantPropagationAnalyzer} for the provided program
	 * @param program the program
	 * @return the appropriate ConstantPropagationAnalyzer
	 */
	public static ConstantPropagationAnalyzer getConstantAnalyzer(Program program) {
        final AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        final List<ConstantPropagationAnalyzer> analyzers = 
            ClassSearcher.getInstances(ConstantPropagationAnalyzer.class);
        for (ConstantPropagationAnalyzer analyzer : analyzers) {
            if (analyzer.canAnalyze(program)) {
                return (ConstantPropagationAnalyzer) mgr.getAnalyzer(analyzer.getName());
            }
        }
        return null;
    }

	/**
	 * Analyzes the provided function with the appropriate {@link ConstantPropagationAnalyzer}
	 * using the provided options.
	 * @param function the function to analyze
	 * @param options the options to use
	 * @param monitor the task monitor
	 * @return a SymbolicPropogator containing the results of the analysis
	 * @throws CancelledException if the analysis is cancelled
	 */
	public static SymbolicPropogator analyzeFunction(Function function, Options options,
		TaskMonitor monitor) throws CancelledException {
            final Program program = function.getProgram();
            final ConstantPropagationAnalyzer analyzer = getConstantAnalyzer(program);
            return analyzeFunction(function, analyzer, options, monitor);
	}

	/**
	 * Analyzes the provided function with the provided ConstantPropagationAnalyzer and options
	 * @param function the function to analyze
	 * @param analyzer the analyzer to use
	 * @param options the options to use
	 * @param monitor the task monitor
	 * @return a SymbolicPropogator containing the results of the analysis
	 * @throws CancelledException if the analysis is cancelled
	 */
	public static SymbolicPropogator analyzeFunction(Function function,
		ConstantPropagationAnalyzer analyzer, Options options,
		TaskMonitor monitor) throws CancelledException {
            final Program program = function.getProgram();
            final SymbolicPropogator symEval = new SymbolicPropogator(program);
            symEval.setParamRefCheck(options.paramRef);
            symEval.setReturnRefCheck(options.returnRef);
            symEval.setStoredRefCheck(options.storedRef);
            analyzer.flowConstants(program, function.getEntryPoint(), function.getBody(),
                                   symEval, monitor);
            return symEval;
	}

	/**
	 * Gets the {@link VarnodeContext} for the provided {@link SymbolicPropogator}
	 * @param propogator the propogator to get the varnode context for
	 * @return the varnode context
	 * @throws Exception if an exception occurs while retrieving the VarnodeContext
	 */
	public static VarnodeContext getVarnodeContext(SymbolicPropogator propogator)
		throws Exception {
			final Field field = propogator.getClass().getDeclaredField("context");
			final VarnodeContext context;
			if (!field.canAccess(propogator)) {
				field.setAccessible(true);
				context = (VarnodeContext) field.get(propogator);
				field.setAccessible(false);
			} else {
				context = (VarnodeContext) field.get(propogator);
			}
			return context;
	}

	/**
	 * A simple class to contain the various settings for a {@link SymbolicPropogator}
	 */
	public static class Options {

		private final boolean paramRef;
		private final boolean returnRef;
		private final boolean storedRef;

		/**
		 * Constructs a new Options instance
		 * @param paramRef true to enable parameter reference checking
		 * @param returnRef true to enable return reference checking
		 * @param storedRef true to enable stored reference checking
		 * @see SymbolicPropogator#setParamRefCheck(boolean)
		 * @see SymbolicPropogator#setReturnRefCheck(boolean)
		 * @see SymbolicPropogator#setStoredRefCheck(boolean)
		 */
		public Options(boolean paramRef, boolean returnRef, boolean storedRef) {
			this.paramRef = paramRef;
			this.returnRef = returnRef;
			this.storedRef = storedRef;
		}
	}
}
