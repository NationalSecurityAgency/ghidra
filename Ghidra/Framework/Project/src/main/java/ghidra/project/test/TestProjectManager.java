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
package ghidra.project.test;

import ghidra.framework.model.ProjectManager;
import ghidra.framework.project.DefaultProjectManager;

/** This class exists to open access to the {@link DefaultProjectManager} for tests */
public class TestProjectManager extends DefaultProjectManager {

	private static ProjectManager projectManager;

	public synchronized static ProjectManager get() {

		// TODO make a static test manager if needed
		//
		// Not sure the best way to proceed here.  The old behavior was to have a shared 
		// project manager.  Having this here made migration easier.  There should be no reason
		// to have a static, shared project manager.
		//
		if (projectManager == null) {
			projectManager = new TestProjectManager();
		}

		return projectManager;
	}

	private TestProjectManager() {
		super();
	}
}
