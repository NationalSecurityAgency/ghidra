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
package ghidra.app.plugin.core.debug.gui.timeoverview;

import java.awt.Color;
import java.util.*;

import docking.action.DockingActionIf;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.util.HelpLocation;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * Interface for services that know how to associate colors with any snap in a program. Instances
 * of these services are discovered and presented as options on the Listing's right margin area.
 */
public interface TimeOverviewColorService extends ExtensionPoint {

	/**
	 * Returns the name of this color service.
	 * 
	 * @return the name of this color service.
	 */
	public String getName();

	/**
	 * Returns the color that this service associates with the given snap.
	 *
	 * @param snap the snap to convert to a color.
	 * @return the color that this service associates with the given snap.
	 */
	public Color getColor(Long snap);

	/**
	 * Sets the trace that this service will provide snap colors for.
	 * 
	 * @param trace the program that this service will provide snap colors for.
	 */
	public void setTrace(Trace trace);

	/**
	 * Sets the component that will be displaying the colors for this
	 * service.
	 * 
	 * @param component the {@link TimeOverviewColorComponent} that will be displaying the colors
	 *            for this service.
	 */
	public void setOverviewComponent(TimeOverviewColorComponent component);

	/**
	 * Returns the tool tip that the {@link TimeOverviewColorComponent} should display when the
	 * mouse is hovering on the pixel that maps to the given snap.
	 *
	 * @param snap the snap for which to get a tooltip.
	 * @return the tooltip text for the given snap.
	 */
	public String getToolTipText(Long snap);

	/**
	 * Returns a list of popup actions to be shown when the user right-clicks on the
	 * {@link TimeOverviewColorComponent} associated with this service.
	 *
	 * @return the list of popup actions.
	 */
	public List<DockingActionIf> getActions();

	/**
	 * Returns the {@link HelpLocation} for this service
	 * 
	 * @return the {@link HelpLocation} for this service
	 */
	public HelpLocation getHelpLocation();

	/**
	 * Initialize the service which typically is used to read options for the service.
	 * 
	 * @param tool the {@link PluginTool} using this service.
	 */
	public void initialize(PluginTool tool);

	/**
	 * Returns the current trace used by the service.
	 * 
	 * @return the current trace used by the service.
	 */
	public Trace getTrace();

	/**
	 * Set the plugin
	 * 
	 * @param plugin overview plugin
	 */
	public void setPlugin(TimeOverviewColorPlugin plugin);

	/**
	 * Get the snap for a given pixel's time coordinate
	 * 
	 * @param pixel location in the display
	 * @return snap
	 */
	public Long getSnap(int pixel);

	/**
	 * Set the indices for mapping pixels->indices->snaps (and vice-versa)
	 * 
	 * @param set tree-set of snaps
	 */
	public void setIndices(TreeSet<Long> set);

	/**
	 * Get the display bounds
	 * 
	 * @return bounds time-range to display
	 */
	public Lifespan getBounds();

	/**
	 * Set the display bounds
	 * 
	 * @param bounds time-range to display
	 */
	public void setBounds(Lifespan bounds);

}
