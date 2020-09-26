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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractAnalyzer implements Analyzer {
	private final String name;
	private final AnalyzerType type;
	private final String description;
	private boolean defaultEnablement = false;
	private boolean supportsOneTimeAnalysis;
	private boolean isPrototype = false;
	private AnalysisPriority priority = AnalysisPriority.LOW_PRIORITY;

	protected AbstractAnalyzer(String name, String description, AnalyzerType type) {
		this.name = name;
		this.type = type;
		this.description = description;
	}

	protected void setPriority(AnalysisPriority priority) {
		this.priority = priority;
	}

	protected void setDefaultEnablement(boolean b) {
		this.defaultEnablement = b;
	}

	protected void setSupportsOneTimeAnalysis() {
		supportsOneTimeAnalysis = true;
	}

	protected void setSupportsOneTimeAnalysis(boolean supportsOneTimeAnalysis) {
		this.supportsOneTimeAnalysis = supportsOneTimeAnalysis;
	}

	protected void setPrototype() {
		isPrototype = true;
	}

	@Override
	public final String getName() {
		return name;
	}

	@Override
	public final AnalyzerType getAnalysisType() {
		return type;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return defaultEnablement;
	}

	@Override
	public final boolean supportsOneTimeAnalysis() {
		return supportsOneTimeAnalysis;
	}

	@Override
	public final String getDescription() {
		return description == null ? "No Description" : description;
	}

	@Override
	public final AnalysisPriority getPriority() {
		return priority;
	}

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return true;
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		// do nothing
	}

	@Override
	public void analysisEnded(Program program) {
		// do nothing
	}

	@Override
	public final boolean isPrototype() {
		return isPrototype;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// do nothing
	}

}
