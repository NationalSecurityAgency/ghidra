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

import java.util.function.Function;

import docking.DockingWindowManager;
import docking.Tool;
import ghidra.framework.model.DomainFile;

public enum PluginToolUtils {
	;

	/**
	 * Attempts the given action in all running tools, starting with the active one, if applicable
	 * 
	 * <p>
	 * This will stop once the given action returns a non-null result, and return that result.
	 * 
	 * @param <T> the type of result
	 * @param tool the front-end tool, whose running plugin tools to try
	 * @param action the action to apply to each plugin tool
	 * @return the first non-null result of the action, or null if all plugin tools were exhausted
	 */
	public static <T> T inRunningToolsPreferringActive(PluginTool tool,
			Function<? super PluginTool, ? extends T> action) {
		Tool activeTool = DockingWindowManager.getActiveInstance().getTool();
		if (activeTool instanceof PluginTool) {
			PluginTool activePluginTool = (PluginTool) activeTool;
			T result = action.apply(activePluginTool);
			if (result != null) {
				return result;
			}
		}
		for (PluginTool pt : tool.getToolServices().getRunningTools()) {
			T result = action.apply(pt);
			if (result != null) {
				return result;
			}
		}
		return null;
	}

	/**
	 * Opens the given domain file in the most recent tool which can accept it, or it launches a new
	 * tool to accept it
	 * 
	 * <p>
	 * TODO: This currently fails in the "most-recent" aspect if a non-compatible tool has focus. In
	 * that case, it'll pick any compatible tool, no matter how recently it had focus.
	 * 
	 * @param tool the front-end tool
	 * @param domainFile the domain file to open
	 * @return the (possibly new) plugin tool which accepted the domain file
	 */
	public static PluginTool openInMostRecentOrLaunchedCompatibleTool(PluginTool tool,
			DomainFile domainFile) {
		DomainFile[] data = new DomainFile[] { domainFile };
		PluginTool result = inRunningToolsPreferringActive(tool, pt -> {
			return pt.acceptDomainFiles(data) ? pt : null;
		});
		if (result != null) {
			return result;
		}
		return tool.getToolServices().launchDefaultTool(domainFile);
	}

	/**
	 * Get the service for the given class from the most recent tool having it
	 * 
	 * <p>
	 * TODO: This currently fails in the "most-recent" aspect if a non-compatible tool has focus. In
	 * that case, it'll pick any compatible tool, no matter how recently it had focus.
	 * 
	 * @param <T> the type of the service
	 * @param tool the front-end tool
	 * @param serviceClass the class of the service
	 * @return the found service, or {@code null} if no running tool has it
	 */
	public static <T> T getServiceFromRunningCompatibleTool(PluginTool tool,
			Class<T> serviceClass) {
		return inRunningToolsPreferringActive(tool, pt -> pt.getService(serviceClass));
	}
}
