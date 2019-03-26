/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.framework.model.*;

import java.io.*;
import java.util.Set;

public class ToolServicesAdapter implements ToolServices {

	@Override
	public void addDefaultToolChangeListener(DefaultToolChangeListener listener) {
	}

	@Override
	public boolean canAutoSave(Tool tool) {
		return true;
	}

	@Override
	public void closeTool(Tool tool) {
		// override
	}

	@Override
	public void displaySimilarTool(Tool tool, DomainFile domainFile, PluginEvent event) {
		// override
	}

	@Override
	public void exportTool(File location, Tool tool) throws FileNotFoundException, IOException {
		// override
	}

	@Override
	public Set<ToolTemplate> getCompatibleTools(Class<? extends DomainObject> domainClass) {
		return null;
	}

	@Override
	public Set<ToolAssociationInfo> getContentTypeToolAssociations() {
		return null;
	}

	@Override
	public ToolTemplate getDefaultToolTemplate(DomainFile domainFile) {
		return null;
	}

	@Override
	public Tool[] getRunningTools() {
		return null;
	}

	@Override
	public ToolChest getToolChest() {
		return null;
	}

	@Override
	public Tool launchDefaultTool(DomainFile domainFile) {
		return null;
	}

	@Override
	public Tool launchTool(String toolName, DomainFile domainFile) {
		return null;
	}

	@Override
	public void removeDefaultToolChangeListener(DefaultToolChangeListener listener) {
		// override
	}

	@Override
	public void saveTool(Tool tool) {
		// override
	}

	@Override
	public void setContentTypeToolAssociations(Set<ToolAssociationInfo> infos) {
		// override
	}

}
