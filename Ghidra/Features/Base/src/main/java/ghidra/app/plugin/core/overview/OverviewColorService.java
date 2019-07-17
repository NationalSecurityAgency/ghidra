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
package ghidra.app.plugin.core.overview;

import java.awt.Color;
import java.util.List;

import docking.action.DockingActionIf;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * Interface for services that know how to associate colors with any address in a program.
 * Instances of these services are discovered and presented as options on the Listing's right
 * margin area.
 */
public interface OverviewColorService extends ExtensionPoint {

	/**
	 * Returns the name of this color service.
	 * @return  the name of this color service.
	 */
	public String getName();

	/**
	 * Returns the color that this service associates with the given address.
	 *
	 * @param address the address for with to get a color.
	 * @return the color that this service associates with the given address.
	 */
	public Color getColor(Address address);

	/**
	 * Sets the program that this service will provide address colors for.
	 * @param program the program that this service will provide address colors for.
	 */
	public void setProgram(Program program);

	/**
	 * Sets the {@link OverviewColorComponent} that will be displaying the colors for this service.
	 * @param component the {@link OverviewColorComponent} that will be displaying the colors for this service.
	 */
	public void setOverviewComponent(OverviewColorComponent component);

	/**
	 * Returns the tool tip that the {@link OverviewColorComponent} should display when the mouse
	 * is hovering on the pixel that maps to the given address.
	 *
	 * @param address the address for which to get a tooltip.
	 * @return the tooltip text for the given address.
	 */
	public String getToolTipText(Address address);

	/**
	 * Returns a list of popup actions to be shown when the user right-clicks on the {@link OverviewColorComponent}
	 * associated with this service.
	 *
	 * @return the list of popup actions.
	 */
	public List<DockingActionIf> getActions();

	/**
	 * Returns the {@link HelpLocation} for this service
	 * @return  the {@link HelpLocation} for this service
	 */
	public HelpLocation getHelpLocation();

	/**
	 * Initialize the service which typically is used to read options for the service.
	 * @param tool the {@link PluginTool} using this service.
	 */
	public void initialize(PluginTool tool);

	/**
	 * Returns the current program used by the service.
	 * @return the current program used by the service.
	 */
	public Program getProgram();

}
