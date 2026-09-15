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
package ghidra.app.plugin.core.functiongraph.mvc;

import java.util.List;

import docking.action.DockingAction;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.functiongraph.FGColorProvider;
import ghidra.app.plugin.core.functiongraph.FunctionGraphPlugin;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * A simple class that allows us to re-use parts of the {@link FunctionGraph} API by abstracting
 * away the {@link FunctionGraphPlugin}.  The env allows the controller to get the state of the 
 * graph, the state of the tool and to share resources among graphs.
 */
public interface FgEnv {

	public PluginTool getTool();

	public Program getProgram();

	public FunctionGraphOptions getOptions();

	public FGColorProvider getColorProvider();

	public List<FGLayoutProvider> getLayoutProviders();

	/**
	 * Adds the given action to the provider used by this environment.
	 * @param action the action
	 */
	public void addLocalAction(DockingAction action);

	/**
	 * Returns the graph format manager that can be shared amongst all graphs.
	 * @return the graph format manager that can be shared amongst all graphs.
	 * @see #setUserDefinedFormat(FormatManager)
	 */
	public FormatManager getUserDefinedFormat();

	/**
	 * Sets the graph format manager that can be shared amongst all graphs.
	 * @param format the format manager
	 * @see #getUserDefinedFormat()
	 */
	public void setUserDefinedFormat(FormatManager format);

	public Navigatable getNavigatable();

	/**
	 * The tool location is the program location shared by all plugins.  Disconnected graphs my not
	 * be using this location.
	 * @return the location
	 * @see #getGraphLocation()
	 */
	public ProgramLocation getToolLocation();

	/**
	 * Sets the selection for this function graph environment.  If the graph is connected to the 
	 * tool, then the selection will be sent to the tool as well as to the graph.
	 * @param selection the selection
	 */
	public void setSelection(ProgramSelection selection);

	/**
	 * Graph location is the program location inside of the graph, which may differ from that of the
	 * tool, such as for disconnected graphs.
	 * @return the location
	 * @see #getToolLocation()
	 */
	public ProgramLocation getGraphLocation();
}
