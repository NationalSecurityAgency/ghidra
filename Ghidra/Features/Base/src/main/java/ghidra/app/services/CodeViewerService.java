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
package ghidra.app.services;

import javax.swing.JComponent;

import docking.action.DockingAction;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.field.Field;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.ProgramDropProvider;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * Service provided by a plugin that shows the listing from a Program, i.e., a
 * Code Viewer. The service allows other plugins to add components and 
 * actions local to the Code Viewer.
 *  
 * 
 */
@ServiceInfo(defaultProvider = CodeBrowserPlugin.class)
public interface CodeViewerService {

	/**
	 * Add a provider that shows an overview of the program.
	 * @param overviewProvider provider to add
	 */
	public void addOverviewProvider(OverviewProvider overviewProvider);

	/**
	 * Remove a provider that shows an overview of the program.
	 * @param overviewProvider provider to remove
	 */
	public void removeOverviewProvider(OverviewProvider overviewProvider);

	/**
	 * Add a provider that shows markers in a program for the portion 
	 * that is visible.
	 * @param marginProvider provider to add
	 */
	public void addMarginProvider(MarginProvider marginProvider);

	/**
	 * Remove a provider that shows markers in a program for the portion 
	 * that is visible.
	 * @param marginProvider provider to remove
	 */
	public void removeMarginProvider(MarginProvider marginProvider);

	/**
	 * Add an action that is local to the Code Viewer.
	 * @param action local action to add
	 */
	public void addLocalAction(DockingAction action);

	/**
	 * Remove the local action from the Code Viewer.
	 * @param action local action to remove
	 */
	public void removeLocalAction(DockingAction action);

	/**
	 * Add a provider that will be notified for drag and drop actions.
	 * @param provider for drag and drop
	 */
	public void addProgramDropProvider(ProgramDropProvider provider);

	/**
	 * Add a listener that is notified when a mouse button is pressed.
	 * @param listener
	 */
	public void addButtonPressedListener(ButtonPressedListener listener);

	/**
	 * Remove the button pressed listener.
	 * @param listener
	 */
	public void removeButtonPressedListener(ButtonPressedListener listener);

	/**
	 * Set the highlight  provider. The existing provider is replaced
	 * with the given provider.
	 * @param provider The provider to set.
	 * @param program The program with which to associate the given provider.
	 */
	public void setHighlightProvider(HighlightProvider provider, Program program);

	/**
	 * Remove the highlight provider.
	 * @param provider the provider to remove.
	 * @param program the program associated with the given provider.
	 */
	public void removeHighlightProvider(HighlightProvider provider, Program program);

	/**
	 * Set a listing panel on the code viewer.
	 * @param listingPanel the panel to add.
	 */
	public void setListingPanel(ListingPanel listingPanel);

	/**
	 * Set the {@link CoordinatedListingPanelListener} for this listing.
	 * @param listener the listener to add.
	 */
	public void setCoordinatedListingPanelListener(CoordinatedListingPanelListener listener);

	/**
	 * Remove the given listing panel from the code viewer.
	 */
	public void removeListingPanel(ListingPanel listingPanel);

	/**
	 * Get Current view that the CodeViewer is showing. 
	 */
	public AddressSetView getView();

	/**
	 * Commands the code viewer to position the cursor at the given location.
	 * @param loc the location at which to position the cursor.
	 * @param centerOnScreen if true, the location will be placed in the center of the display
	 * window
	 * @return true if the location exists.
	 */
	public boolean goTo(ProgramLocation loc, boolean centerOnScreen);

	/**
	 * Return the fieldPanel.
	 */
	public FieldPanel getFieldPanel();

	/**
	 * Returns the current address-index-map
	 */
	public AddressIndexMap getAddressIndexMap();

	public FormatManager getFormatManager();

	/**
	 * Place a component in the North area of the CodeViewer.
	 * @param comp component to place in the North area of the CodeViewer
	 */
	public void setNorthComponent(JComponent comp);

	/**
	 * tells the browser to rebuild the display.
	 */
	public void updateDisplay();

	/**
	 * Gets the current ListingLayoutModel;
	 * @return the current ListingLayoutModel;
	 */
	public ListingModel getListingModel();

	/**
	 * Gets the navigatable for the code viewer service.
	 * @return the navigatable for the code viewer service.
	 */
	public Navigatable getNavigatable();

	/**
	 * Get the main Listing panel for the code viewer service.
	 * @return the listing panel.
	 */
	public ListingPanel getListingPanel();

	/**
	 * Returns a String representing the current character-based selection of the currently 
	 * selected field.  If there is no selection, or if there is a {@link ProgramSelection} 
	 * (which spans multiple fields), then this method will return null.   
	 * <p>
	 * To know which field contains the selection, 
	 * 
	 * @return the currently selected text <b>within a given field</b>
	 */
	public String getCurrentFieldTextSelection();

	/**
	 * Returns the current field under the cursor.
	 * @return the current field under the cursor.
	 */
	public Field getCurrentField();

	/**
	 * Returns the current cursor location.
	 * @return the current cursor location.
	 */
	public ProgramLocation getCurrentLocation();

	/**
	 * Returns the current program selection (which crosses multiple fields).
	 * @return the current program selection.
	 */
	public ProgramSelection getCurrentSelection();

	/**
	 * Adds a listener to be notified when the set of visible addresses change.
	 * @param listener the listener to be notified;
	 */
	public void addListingDisplayListener(AddressSetDisplayListener listener);

	/**
	 * Removes listener from being notified when the set of visible addresses change.
	 * @param listener the listener to be notified;
	 */
	public void removeListingDisplayListener(AddressSetDisplayListener listener);
}
