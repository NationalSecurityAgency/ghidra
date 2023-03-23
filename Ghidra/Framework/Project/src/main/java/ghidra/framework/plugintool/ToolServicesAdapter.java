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

import java.io.*;
import java.net.URL;
import java.util.Collection;
import java.util.Set;

import ghidra.framework.model.*;

public class ToolServicesAdapter implements ToolServices {

	@Override
	public boolean canAutoSave(PluginTool tool) {
		return true;
	}

	@Override
	public void closeTool(PluginTool tool) {
		// override
	}

	@Override
	public void displaySimilarTool(PluginTool tool, DomainFile domainFile, PluginEvent event) {
		// override
	}

	@Override
	public File exportTool(ToolTemplate tool) throws FileNotFoundException, IOException {
		return null;
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
	public ToolTemplate getDefaultToolTemplate(String contentType) {
		return null;
	}

	@Override
	public PluginTool[] getRunningTools() {
		return null;
	}

	@Override
	public ToolChest getToolChest() {
		return null;
	}

	@Override
	public PluginTool launchDefaultTool(Collection<DomainFile> domainFile) {
		return null;
	}

	@Override
	public PluginTool launchTool(String toolName, Collection<DomainFile> domainFile) {
		return null;
	}

	@Override
	public PluginTool launchDefaultToolWithURL(URL url) {
		return null;
	}

	@Override
	public PluginTool launchToolWithURL(String toolName, URL url) {
		return null;
	}

	@Override
	public void saveTool(PluginTool tool) {
		// override
	}

	@Override
	public void setContentTypeToolAssociations(Set<ToolAssociationInfo> infos) {
		// override
	}

}
