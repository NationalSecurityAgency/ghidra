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
package ghidra.framework.main;

import ghidra.framework.model.Project;
import ghidra.util.exception.AssertException;

/**
 * Class with static methods to maintain application info, e.g., a handle to the
 * tool that is the Ghidra Project Window, the user's name, etc.
 */
public class AppInfo {

	private static FrontEndTool tool;
	private static Project activeProject;

	static void setFrontEndTool(FrontEndTool t) {
		tool = t;
	}

	static void setActiveProject(Project p) {
		activeProject = p;
	}

	public static FrontEndTool getFrontEndTool() {
		assertFrontEndRunning();
		return tool;
	}

	public static Project getActiveProject() {
		return activeProject;
	}

	public static void exitGhidra() {
		assertFrontEndRunning();
		tool.exit();
	}

	private static void assertFrontEndRunning() {
		if (tool == null) {
			throw new AssertException(
				"Cannot use " + AppInfo.class.getSimpleName() + " without a Front End running");
		}
	}
}
