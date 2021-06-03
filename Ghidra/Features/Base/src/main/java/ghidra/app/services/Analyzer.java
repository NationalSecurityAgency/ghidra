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
package ghidra.app.services;

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * NOTE:  ALL ANALYZER CLASSES MUST END IN "Analyzer".  If not,
 * the ClassSearcher will not find them.
 * 
 * Interface to perform automatic analysis.
 */
public interface Analyzer extends ExtensionPoint {
	/**
	 * Get the name of this analyzer
	 * @return analyzer name
	 */
	public String getName();

	/**
	 * Get the type of analysis this analyzer performs
	 * @return analyze type
	 */
	public AnalyzerType getAnalysisType();

	/**
	 * Returns true if this analyzer should be enabled by default.  Generally useful
	 * analyzers should return true. Specialized analyzers should return false;
	 */
	public boolean getDefaultEnablement(Program program);

	/**
	 * Returns true if it makes sense for this analyzer to directly invoked on an address or
	 * addressSet.  The AutoAnalyzer plug-in will automatically create an action for each
	 * analyzer that returns true.
	 */
	public boolean supportsOneTimeAnalysis();

	/**
	 * Get a longer description of what this analyzer does.
	 * @return analyzer description
	 */
	public String getDescription();

	/**
	 * Get the priority that this analyzer should run at.
	 * @return analyzer priority
	 */
	public AnalysisPriority getPriority();

	/**
	 * Can this analyzer work on this program. 
	 * @param program program to be analyzed
	 * @return true if this analyzer can analyze this program
	 */
	public boolean canAnalyze(Program program);

	/**
	 * Called when the requested information type has been added.
	 * (ie: function added.)
	 * 
	 * @param program program to analyze
	 * @param set AddressSet of locations that have been added
	 * @param monitor monitor that indicates progress and indicates whether
	 * the user canceled the analysis
	 * @param log a message log to record analysis information
	 * @return true if the analysis succeeded
	 */
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException;

	/**
	 * Called when the requested information type has been removed.
	 * (ie: function removed.)
	 *
	 * @param program program to analyze
	 * @param set AddressSet of locations that have been added
	 * @param monitor monitor that indicates progress and indicates whether
	 * the user canceled the analysis
	 * @param log a message log to record analysis information
	 * @return true if the analysis succeeded
	 */
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException;

	/**
	 * Analyzers should register their options with associated default value, help content and
	 * description
	 * @param options the program options/property list that contains the options
	 * @param program program to be analyzed
	 */
	public void registerOptions(Options options, Program program);

	/**
	 * Analyzers should initialize their options from the values in the given Options, 
	 * providing appropriate default values.
	 * @param options the program options/property list that contains the options
	 * @param program program to be analyzed
	 */
	public void optionsChanged(Options options, Program program);

	/**
	 * Called when an auto-analysis session ends. This notifies the analyzer so it can clean up any 
	 * resources that only needed to be maintained during a single auto-analysis session.
	 * @param program the program that was just completed being analyzed
	 */
	public void analysisEnded(Program program);

	/**
	 * Returns true if this analyzer is a prototype.
	 * @return true if this analyzer is a prototype
	 */
	public boolean isPrototype();

}
