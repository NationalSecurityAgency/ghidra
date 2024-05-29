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
package ghidra.app.plugin;

import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.plugintool.util.PluginDescription;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * A listing of commonly used {@link PluginDescription} category names.
 * <p>
 * Note - the Front End tool automatically include plugins that: 1) implement 
 * {@link ApplicationLevelPlugin}, have the {@link PluginStatus#RELEASED}, and do not have the 
 * {@link #EXAMPLES} category.  If you wish to create an {@link ApplicationLevelPlugin} that is not
 * automatically included in the Front End, the easiest way to do that is to mark its status as
 * {@link PluginStatus#STABLE}.
 */
public interface PluginCategoryNames {

	public String ANALYSIS = "Analysis";

	// common to tools that open programs
	public String COMMON = "Common";
	public String CODE_VIEWER = "Code Viewer";
	public String DEBUGGER = "Debugger";
	public String DIAGNOSTIC = "Diagnostic";
	public String EXAMPLES = "Examples";
	public String FRAMEWORK = "Framework";
	public String GRAPH = "Graph";
	public String NAVIGATION = "Navigation";
	public String SEARCH = "Search";
	public String SELECTION = "Selection";
	public String PROGRAM_ORGANIZATION = "Program Organization";
}
