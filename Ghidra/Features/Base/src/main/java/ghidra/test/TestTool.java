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
package ghidra.test;

import docking.DockingWindowManager;
import ghidra.framework.model.Project;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;

public class TestTool extends GhidraTool {
	public final static String NAME = "Test Tool";

	public TestTool(Project project) {
		super(project, NAME);
		winMgr.setWindowsOnTop(true);
	}

	@Override
	protected DockingWindowManager createDockingWindowManager(boolean isDockable, boolean hasStatus,
			boolean isModal) {
		return new DockingWindowManager(this, null, isModal, isDockable, hasStatus, null);
	}

	@Override
	public void close() {
		if (isExecutingCommand()) {
			throw new AssertException("Attempted to close tool while background command running");
		}

		Runnable r = () -> {
			exit();
			if (getProject().getToolServices() != null) {
				getProject().getToolServices().closeTool(TestTool.this);
			}
		};

		SystemUtilities.runSwingNow(r);
	}
}
