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
package ghidra.framework.plugintool;

import ghidra.framework.model.Project;

/**
 * Plugin event for notifying when a project is opened or closed. Note this is only applicable for
 * FrontEndTool plugins.
 */
public class ProjectPluginEvent extends PluginEvent {
	private static final String NAME = "Program Opened";
	private Project project;

	/**
	 * Constructor 
	 * @param sourceName the name of source of the event
	 * @param project if non-null, the project that was opened; otherwise the current was closed.
	 */
	public ProjectPluginEvent(String sourceName, Project project) {
		super(sourceName, NAME);
		this.project = project;
	}

	/**
	 * Returns the project that was opened or null if the project was closed.
	 * @return the project that was opened or null if the project was closed.
	 */
	public Project getProject() {
		return project;
	}
}
