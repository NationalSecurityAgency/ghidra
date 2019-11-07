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
package ghidra.app.plugin.core.navigation.locationreferences;

import java.awt.Color;

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.GhidraOptions;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.*;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;

/**
 * Handles highlighting for {@link LocationReferencesProvider}.
 */
class LocationReferencesHighlighter {
	private static final String MARKER_SET_DESCRIPTION = "Shows the location of references " +
		"currently displayed in the Location References window.";

	private static final String OPTIONS_TITLE = GhidraOptions.OPTION_SEARCH_TITLE;
	private static final String HIGHLIGHT_COLOR_KEY =
		"Reference Search" + GhidraOptions.DELIMITER + "Highlight Match Color";
	private static final String HIGHLIGHT_COLOR_DESCRIPTION =
		"The highlight color of matches for the 'Show References' searcher";
	private static Color DEFAULT_HIGHLIGHT_COLOR = new Color(168, 202, 242);

	private boolean isHighlighting = false;
	private final Navigatable navigatable;
	private LocationReferencesProvider provider;
	private LocationReferencesPlugin locationReferencesPlugin;

	private HighlightProvider highlightProvider;
	private MarkerRemover markerRemover;
	private Color highlightColor;
	private OptionsChangeListener optionsListener = new OptionsChangeListener() {
		@Override
		public void optionsChanged(ToolOptions options, String name, Object oldValue,
				Object newValue) {
			if (name.equals(HIGHLIGHT_COLOR_KEY)) {
				highlightColor = (Color) newValue;
			}
		}
	};

	// This is a bit unusual, but we do this here, since this highlighter will come and 
	// go with each search.  If we do not register a priori, then the option will not appear in the
	// tool until a search has happened, which is odd.
	static void registerHighlighterOptions(LocationReferencesPlugin plugin) {
		ToolOptions options = plugin.getTool().getOptions(OPTIONS_TITLE);
		options.registerOption(HIGHLIGHT_COLOR_KEY, DEFAULT_HIGHLIGHT_COLOR,
			plugin.getHelpLocation(), HIGHLIGHT_COLOR_DESCRIPTION);
	}

	LocationReferencesHighlighter(LocationReferencesPlugin locationReferencesPlugin,
			LocationReferencesProvider provider, Navigatable navigatable) {
		this.locationReferencesPlugin = locationReferencesPlugin;
		this.navigatable = navigatable;
		if (provider == null) {
			throw new NullPointerException("null provider not allowed.");
		}

		this.provider = provider;

		ToolOptions options = locationReferencesPlugin.getTool().getOptions(OPTIONS_TITLE);
		highlightColor = options.getColor(HIGHLIGHT_COLOR_KEY, DEFAULT_HIGHLIGHT_COLOR);
		options.addOptionsChangeListener(optionsListener);
	}

	void setHighlightingEnabled(boolean enabled) {
		isHighlighting = enabled;
		updateHighlights();
	}

	private void updateHighlights() {
		PluginTool tool = locationReferencesPlugin.getTool();

		if (tool == null) { // happens during tool exit
			return;
		}

		if (!navigatable.supportsHighlight()) {
			return;
		}

		Program activeProgram = navigatable.getProgram();
		Program providerProgram = provider.getProgram();

		// no need to highlight if the active provider is not based upon the current program
		if (isHighlighting && (activeProgram != providerProgram)) {
			return;
		}

		LocationDescriptor locationDescriptor = provider.getLocationDescriptor();
		DataTypeManagerService dataTypeManagerService =
			tool.getService(DataTypeManagerService.class);
		if (isHighlighting) {
			// we know that if the address set is the same, then the marking and highlighting
			// have not changed
			AddressSet set = provider.getReferenceAddresses(providerProgram);

			// markers
			setHighlightMarkers(tool, set);

			// listing panel highlights
			highlightProvider = new LocationReferencesHighlightProvider();
			navigatable.setHighlightProvider(highlightProvider, providerProgram);

			// check for data types (the user may have changed the selected datatype, so
			// re-select it)
			selectDataType(dataTypeManagerService, locationDescriptor, true);
		}
		else {
			// markers
			clearMarkers();

			// deselect in data type manager
			selectDataType(dataTypeManagerService, locationDescriptor, false);
		}
	}

	private void setHighlightMarkers(PluginTool tool, AddressSet addressSet) {
		if (!navigatable.supportsMarkers()) {
			return;
		}

		clearMarkers();

		MarkerService markerService = tool.getService(MarkerService.class);
		if (markerService == null) {
			return; // we still work without the marker service
		}

		Program program = navigatable.getProgram();

		// creating the marker set adds it, so be sure to remove the marker set after we
		// create it
		MarkerSet currentMarkerSet =
			markerService.createPointMarker("References To", MARKER_SET_DESCRIPTION, program,
				MarkerService.HIGHLIGHT_PRIORITY, false, true, false, highlightColor, null);
		markerService.removeMarker(currentMarkerSet, program);
		markerService.setMarkerForGroup(MarkerService.HIGHLIGHT_GROUP, currentMarkerSet, program);
		currentMarkerSet.add(addressSet);
		markerRemover = new MarkerRemover(currentMarkerSet, markerService, program);
	}

	private void clearMarkers() {
		if (markerRemover != null) {
			markerRemover.dispose();
			markerRemover = null;
		}

		// listing panel highlights
		Program providerProgram = provider.getProgram();
		navigatable.removeHighlightProvider(highlightProvider, providerProgram);
	}

	private void selectDataType(DataTypeManagerService dataTypeManagerService,
			LocationDescriptor locationDescriptor, boolean enable) {

		if (!(locationDescriptor instanceof DataTypeLocationDescriptor)) {
			return;
		}

		if (dataTypeManagerService == null) {
			return;
		}

		DataTypeLocationDescriptor dataTypeDescriptor =
			(DataTypeLocationDescriptor) locationDescriptor;

		// if enabled, then select the data type from the descriptor, otherwise, deselect by using
		// null
		DataType locationDataType = null;
		if (enable) {
			locationDataType = dataTypeDescriptor.getSourceDataType();
			locationDataType = ReferenceUtils.getBaseDataType(locationDataType);
		}

		dataTypeManagerService.setDataTypeSelected(locationDataType);
	}

	LocationReferencesProvider getCurrentHighlightProvider() {
		return provider;
	}

	void dispose() {
		ToolOptions options = locationReferencesPlugin.getTool().getOptions(OPTIONS_TITLE);
		options.removeOptionsChangeListener(optionsListener);
		clearMarkers();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class LocationReferencesHighlightProvider implements HighlightProvider {
		private final Highlight[] NO_HIGHLIGHTS = new Highlight[0];

		// for the Class parameter
		@Override
		public Highlight[] getHighlights(String text, Object obj,
				Class<? extends FieldFactory> fieldFactoryClass, int cursorTextOffset) {
			if (text == null) {
				return NO_HIGHLIGHTS;
			}

			LocationDescriptor locationDescriptor = provider.getLocationDescriptor();
			return locationDescriptor.getHighlights(text, obj, fieldFactoryClass, highlightColor);
		}

	}

	private class MarkerRemover {
		private final MarkerSet markerSet;
		private final MarkerService markerSerivce;
		private final Program program;

		private MarkerRemover(MarkerSet markerSet, MarkerService markerSerivce, Program program) {
			this.markerSet = markerSet;
			this.markerSerivce = markerSerivce;
			this.program = program;
		}

		void dispose() {
			markerSerivce.removeMarker(markerSet, program);
		}

		@Override
		public String toString() {
			return "MarkerRemover [MarkerSet=" + markerSet.getName() + "]";
		}
	}
}
