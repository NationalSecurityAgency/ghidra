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
/*
 * AnalysisBackgroundCommand.java
 * 
 * Created on Aug 27, 2003
 */
package ghidra.app.plugin.core.analysis;

import ghidra.framework.cmd.MergeableBackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;

/**
 * Background task to artificially kick off Auto analysis by
 * calling anything that analyzes bytes.
 * 
 * 
 *
 */
public class AnalysisBackgroundCommand extends MergeableBackgroundCommand {
	private AutoAnalysisManager mgr;
	private boolean markAsAnalyzed;

	/**
	 * Background Command to perform Auto Analysis on a program.
	 * 
	 * @param mgr the program's AutoAnalysisManager.
	 * @param markAsAnalyzed true to set the analyzed flag after analysis.
	 */
	public AnalysisBackgroundCommand(AutoAnalysisManager mgr, boolean markAsAnalyzed) {
		super("Auto Analysis", true, true, false);
		this.mgr = mgr;
		this.markAsAnalyzed = markAsAnalyzed;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		if (markAsAnalyzed) {
			GhidraProgramUtilities.setAnalyzedFlag((Program) obj, true);
		}
		mgr.startAnalysis(monitor);
		return true;
	}

	/** Merges the properties of the two commands */
	@Override
	public MergeableBackgroundCommand mergeCommands(MergeableBackgroundCommand command) {
		SystemUtilities.assertTrue(command instanceof AnalysisBackgroundCommand,
			"This code assumes that the "
				+ "two commands are both AnalysisBackgroundCommands and this is not the case.");

		AnalysisBackgroundCommand abc = (AnalysisBackgroundCommand) command;
		SystemUtilities.assertTrue(mgr == abc.mgr, "This code assumes that the "
			+ "managers of the two commands are the same instance and this is not the case.");

		// once we encounter a markAsAnalyzed value that is true, then leave it on
		markAsAnalyzed = markAsAnalyzed | abc.markAsAnalyzed;
		return this;
	}
}
