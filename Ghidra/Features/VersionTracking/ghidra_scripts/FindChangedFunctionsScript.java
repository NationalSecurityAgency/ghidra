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
// An example of how to use Version Tracking to find matching and non-matching functions between
// two different versions of the same program.
//@category Examples.Version Tracking

import java.util.Collection;
import java.util.Set;

import ghidra.feature.vt.GhidraVersionTrackingScript;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class FindChangedFunctionsScript extends GhidraVersionTrackingScript {

	@Override
	protected void run() throws Exception {
		Project project = state.getProject();
		if (project == null) {
			throw new RuntimeException("No project open");
		}
		
		// Prompt the user to load the two programs that will be analyzed.
		// This will only allow you to select programs from the currently-open 
		// project in Ghidra, so import them if you haven't already.
		Program p1 = askProgram("Program1_Version1");
		Program p2 = askProgram("Program1_Version2");
				
		// Make sure the selected programs are not open and locked by Ghidra. If so,
		// warn the user.
		if (areProgramsLocked(p1, p2)) {
			Msg.showError(this, null, "Program is locked!", "One of the programs you selected is locked by Ghidra. Please correct and try again.");
			return;
		}		
				
		// Create a new VT session
		createVersionTrackingSession("new session", p1, p2);

		runCorrelator("Exact Function Instructions Match");

		Set<String> functionNames = getSourceFunctions();

		Collection<VTMatch> matches = getMatchesFromLastRunCorrelator();
		for (VTMatch vtMatch : matches) {
			Function function = getSourceFunction(vtMatch);
			functionNames.remove(function.getName());
			println("Found exact match for " + function.getName());
		}

		for (String functionName : functionNames) {
			println("Did not find exact match for: " + functionName);
		}
	}
	
	/**
	 * Returns true if one of the programs is locked.
	 * <p>
	 * Note: calling {@link Program#isLocked()} does not work here; we must
	 * check to see if one of the programs is the currently-open program.
	 *  
	 * @param p1 the first program
	 * @param p2 the second program
	 * @return true if either program is locked
	 */
	private boolean areProgramsLocked(Program p1, Program p2) {
		return p1 == currentProgram || p2 == currentProgram;
	}
}
