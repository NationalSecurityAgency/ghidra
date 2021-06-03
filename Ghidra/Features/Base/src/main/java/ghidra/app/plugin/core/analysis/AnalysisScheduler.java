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
package ghidra.app.plugin.core.analysis;

import ghidra.app.services.Analyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class AnalysisScheduler {
	private AutoAnalysisManager analysisMgr;
	private Analyzer analyzer;
	private AddressSet removeSet;
	private AddressSet addSet;

	private boolean defaultEnablement;
	private boolean enabled;
	private boolean scheduled;

	AnalysisScheduler(AutoAnalysisManager analysisMgr, Analyzer analyzer) {
		this.analysisMgr = analysisMgr;
		this.analyzer = analyzer;
		if (analyzer.getName().indexOf('.') >= 0) {
			// Use of period will cause analyzer not to appear in options panel
			throw new IllegalArgumentException("Analyzer name may not contain a period: " +
				analyzer.getName());
		}
		defaultEnablement = getDefaultEnablement();
		enabled = defaultEnablement;
		removeSet = new AddressSet();
		addSet = new AddressSet();
	}

	private boolean getDefaultEnablement() {
		Program program = analysisMgr.getProgram();
		boolean defaultEnable = analyzer.getDefaultEnablement(program);
		boolean override = getEnableOverride(defaultEnable);
		if (defaultEnable != override) {
			Msg.warn(AnalysisScheduler.class,
				"Analyzer \'" + analyzer.getName() + "\' for " + program.getName() + " " +
					(override ? "enabled" : "disabled") + " by PSPEC file override");
			defaultEnable = override;
		}
		return defaultEnable;
	}

	synchronized void schedule() {
		// if not scheduled right now, schedule it
		if (!scheduled && (!addSet.isEmpty() || !removeSet.isEmpty())) {
			analysisMgr.schedule(new AnalysisTask(this, analysisMgr.getMessageLog()),
				getPriority());
			scheduled = true;
		}
	}

	synchronized void added(AddressSetView set) {
		if (!enabled) {
			return;
		}

		addSet.add(set);

		schedule();
	}

	synchronized void added(Address addr) {
		if (!enabled) {
			return;
		}

		addSet.add(addr);

		schedule();
	}

	synchronized void removed(AddressSetView set) {
		if (!enabled) {
			return;
		}

		removeSet.add(set);

		schedule();
	}

	synchronized void removed(Address addr) {
		if (!enabled) {
			return;
		}

		removeSet.add(addr);

		schedule();
	}

	Analyzer getAnalyzer() {
		return analyzer;
	}

	private AddressSet getAddedAddressSet() {
		AddressSet oldSet = addSet;
		addSet = new AddressSet();
		return oldSet;
	}

	private AddressSet getRemovedAddressSet() {
		AddressSet oldSet = removeSet;
		removeSet = new AddressSet();
		return oldSet;
	}

	public void optionsChanged(Options options) {
		enabled = options.getBoolean(analyzer.getName(), defaultEnablement);
		analyzer.optionsChanged(options.getOptions(analyzer.getName()), analysisMgr.getProgram());
	}

	public void registerOptions(Options options) {
		Options analyzerOptions = options.getOptions(analyzer.getName());
		options.registerOption(analyzer.getName(), defaultEnablement, null,
			analyzer.getDescription());
		analyzer.registerOptions(analyzerOptions, analysisMgr.getProgram());
	}

	private boolean getEnableOverride(boolean defaultEnable) {
		Language language = analysisMgr.getProgram().getLanguage();

		// get the overall disable property
		boolean allOverriden = false;
		if (language.hasProperty("DisableAllAnalyzers")) {
			allOverriden = true;
		}
		boolean overrideEnable = defaultEnable;
		// let individual analyzers be turned off or on
		String propertyName = "Analyzers." + analyzer.getName();
		if (language.hasProperty(propertyName)) {
			overrideEnable = language.getPropertyAsBoolean(propertyName, defaultEnable);
		}
		else if (allOverriden) {
			overrideEnable = false;
		}

		return overrideEnable;
	}

	public int getPriority() {
		return analyzer.getPriority().priority();
	}

	public String getName() {
		return analyzer.getName();
	}

	public boolean runAnalyzer(Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AddressSetView saveAddSet;
		AddressSetView saveRemoveSet;

		synchronized (this) {
			saveAddSet = getAddedAddressSet();
			saveRemoveSet = getRemovedAddressSet();
			scheduled = false;
		}

		monitor.setMessage(analyzer.getName());
		monitor.setProgress(0);
		boolean result = false;
		if (!saveAddSet.isEmpty()) {
			result |= analyzer.added(program, saveAddSet, monitor, log);
		}

		if (!saveRemoveSet.isEmpty()) {
			result |= analyzer.removed(program, saveRemoveSet, monitor, log);
		}

		return result;
	}

	/**
	 * Notify this analyzer that a run has been canceled.
	 */
	public void runCanceled() {
		// throw away saved up address sets to be analyzed
		getAddedAddressSet();
		getRemovedAddressSet();
		scheduled = false;
	}

	@Override
	public String toString() {
		return analyzer.getName();
	}
}
