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
package ghidra.features.base.codecompare.listing;

import static ghidra.GhidraOptions.*;

import java.awt.Color;

import javax.swing.Icon;

import docking.widgets.fieldpanel.support.ViewerPosition;
import generic.theme.GIcon;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.codebrowser.MarkerServiceBackgroundColorModel;
import ghidra.app.plugin.core.codebrowser.hover.*;
import ghidra.app.plugin.core.marker.MarkerManager;
import ghidra.app.services.*;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.app.util.viewer.util.FieldNavigator;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ListingDiff;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Duo.Side;

/**
 * Represents one side of a dual listing compare window. It holds the listing panel and
 * related state information for one side. 
 */
public class ListingDisplay implements ListingDiffChangeListener {
	private static final Icon CURSOR_LOC_ICON = new GIcon("icon.base.util.listingcompare.cursor");
	private ListingPanel listingPanel;
	private PluginTool tool;
	private ListingDisplayServiceProvider serviceProvider;
	private MarkerManager markerManager;
	private ListingCodeComparisonOptions comparisonOptions;
	private Color cursorHighlightColor;
	private MarkerSet unmatchedMarkers;
	private MarkerSet diffMarkers;
	private MarkerSet currentCursorMarkers;
	private ListingDiffHighlightProvider diffHighlights;
	private FieldNavigator fieldNavigator;
	private ListingDiff listingDiff;
	private Side side;

	public ListingDisplay(PluginTool tool, String owner, ListingDiff listingDiff,
			ListingCodeComparisonOptions comparsionOptions, Side side) {
		this.tool = tool;
		this.listingDiff = listingDiff;
		this.comparisonOptions = comparsionOptions;
		this.side = side;

		FormatManager formatManager = createFormatManager();
		loadOptions();

		listingPanel = new ListingPanel(formatManager);
		// Turn off selection in the listings so it can be set up as desired elsewhere.
		listingPanel.getFieldPanel().enableSelection(false);

		serviceProvider = new ListingDisplayServiceProvider();
		formatManager.setServiceProvider(serviceProvider);
		fieldNavigator = new FieldNavigator(serviceProvider, null);
		setMouseNavigationEnabled(true);
		createMarkerManager(owner);

		listingPanel.addHoverService(new ReferenceListingHover(tool, () -> formatManager));
		listingPanel.addHoverService(new DataTypeListingHover(tool));
		listingPanel.addHoverService(new TruncatedTextListingHover(tool));
		listingPanel.addHoverService(new FunctionNameListingHover(tool));

		listingDiff.addListingDiffChangeListener(this);
		setHoverMode(true);
	}

	private void createMarkerManager(String owner) {
		markerManager = new ListingDisplayMarkerManager(tool, owner);
		markerManager.addChangeListener(e -> listingPanel.repaint());
		MarginProvider marginProvider = markerManager.getMarginProvider();
		listingPanel.addMarginProvider(marginProvider);
		OverviewProvider overviewProvider = markerManager.getOverviewProvider();
		listingPanel.addOverviewProvider(overviewProvider);
	}

	void setProgramLocationListener(ProgramLocationListener listener) {
		listingPanel.setProgramLocationListener(listener);
	}

	private FormatManager createFormatManager() {
		ToolOptions displayOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);

		FormatManager formatManager = new FormatManager(displayOptions, fieldOptions);

		return formatManager;
	}

	public void repaint() {
		listingPanel.getFieldPanel().repaint();
	}

	public void setDiffHighlightProvider(ListingDiffHighlightProvider newDiffHighlights) {
		if (diffHighlights != null) {
			removeHighlightProvider(diffHighlights);
		}

		diffHighlights = newDiffHighlights;

		if (diffHighlights != null) {
			addHighlightProvider(diffHighlights);
		}
	}

	public void addHighlightProvider(ListingHighlightProvider highlightProvider) {
		listingPanel.getFormatManager().addHighlightProvider(highlightProvider);
	}

	public void removeHighlightProvider(ListingHighlightProvider highlightProvider) {
		if (highlightProvider == null) {
			return;
		}
		listingPanel.getFormatManager().removeHighlightProvider(highlightProvider);
	}

	public void addHoverService(ListingHoverService service) {
		listingPanel.addHoverService(service);
	}

	public void showHeader(boolean show) {
		listingPanel.showHeader(show);
		listingPanel.validate();
		listingPanel.invalidate();
	}

	public void setHoverMode(boolean enabled) {
		listingPanel.setHoverMode(enabled);
	}

	public void setView(AddressSetView view) {
		ProgramLocation saved = listingPanel.getProgramLocation();
		listingPanel.setView(view);
		if (saved != null) {
			listingPanel.goTo(saved);
		}
	}

	public boolean isHeaderShowing() {
		return listingPanel.isHeaderShowing();
	}

	public void setProgramView(Program program, AddressSetView view, String name) {
		listingPanel.setProgram(program);
		markerManager.clearAll();
		listingPanel.setView(view);
		AddressIndexMap indexMap = listingPanel.getAddressIndexMap();
		markerManager.getOverviewProvider().setProgram(program, indexMap);
		listingPanel.setBackgroundColorModel(
			new MarkerServiceBackgroundColorModel(markerManager, program, indexMap));
		setUpAreaMarkerSets(program, name);
		if (!view.isEmpty()) {
			goTo(new ProgramLocation(program, view.getMinAddress()));
		}
		repaint();
	}

	void setUpAreaMarkerSets(Program program, String name) {
		if (program == null) {
			return;
		}
		Color diffColor = comparisonOptions.getDiffCodeUnitsBackgroundColor();
		Color unmatchedColor = comparisonOptions.getUnmatchedCodeUnitsBackgroundColor();

		AddressIndexMap indexMap = listingPanel.getAddressIndexMap();
		listingPanel.getFieldPanel().setBackgroundColorModel(new MarkerServiceBackgroundColorModel(
			markerManager, program, indexMap));

		unmatchedMarkers = markerManager.createAreaMarker(name + " Unmatched Code",
			"Instructions that are not matched to an instruction in the other function.",
			program, MarkerService.DIFF_PRIORITY, true, true, true,
			unmatchedColor);
		diffMarkers = markerManager.createAreaMarker(name + " Diffs",
			"Instructions that have a difference.", program, MarkerService.DIFF_PRIORITY,
			true, true, true, diffColor);

		currentCursorMarkers = markerManager.createPointMarker("Cursor",
			"Cursor Location", program, MarkerService.FUNCTION_COMPARE_CURSOR_PRIORITY,
			true, true, true, cursorHighlightColor, CURSOR_LOC_ICON, false);

	}

	public ProgramLocation getProgramLocation() {
		return listingPanel.getProgramLocation();
	}

	private void loadOptions() {
		ToolOptions fieldOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		//
		// 							Unusual Code Alert!
		// In a normal tool, this option is registered by the Code Browse Plugin.  In the VT
		// tool, nobody registers this option.   Our system logs a warning if an option is used
		// but not registered.  So, when in a real tool, use the registered/managed option.
		// Otherwise, just use the default.
		//
		if (fieldOptions.isRegistered(GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR)) {
			cursorHighlightColor = fieldOptions.getColor(GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR,
				DEFAULT_CURSOR_LINE_COLOR);
		}
		else {
			cursorHighlightColor = DEFAULT_CURSOR_LINE_COLOR;
		}

	}

	private class ListingDisplayMarkerManager extends MarkerManager {

		private ListingDisplayMarkerManager(PluginTool tool, String owner) {
			super(owner, tool);
		}

		@Override
		public GoToService getGoToService() {
			return serviceProvider.getService(GoToService.class);
		}
	}

	private class ListingDisplayServiceProvider extends ServiceProviderStub {
		private GoToService goToService;

		ListingDisplayServiceProvider() {
			goToService = new ListingDisplayGoToService(listingPanel);
		}

		@SuppressWarnings("unchecked")
		@Override
		public <T> T getService(Class<T> serviceClass) {
			if (serviceClass == GoToService.class) {
				return (T) goToService;
			}
			return null;
		}
	}

	public void updateCursorMarkers(ProgramLocation location) {
		if (currentCursorMarkers != null) {
			currentCursorMarkers.clearAll();
			if (location != null) {
				currentCursorMarkers.add(location.getAddress());
			}
		}
		repaint();
	}

	private void setAreaMarkers(MarkerSet markers, AddressSetView diffAddresses, Color color) {
		if (markers == null) {
			return;
		}
		markers.setMarkerColor(color);
		markers.clearAll();
		markers.add(diffAddresses);
		repaint();
	}

	public void goTo(ProgramLocation location) {
		if (location != null) {
			listingPanel.goTo(location);
		}
		updateCursorMarkers(location);
	}

	public ListingPanel getListingPanel() {
		return listingPanel;
	}

	void dispose() {
		listingDiff.removeListingDiffChangeListener(this);

		setDiffHighlightProvider(null);
		markerManager.dispose();
		listingPanel.removeButtonPressedListener(fieldNavigator);
		listingPanel.dispose();
	}

	public FormatManager getFormatManager() {
		return listingPanel.getFormatManager();
	}

	public ViewerPosition getViewerPosition() {
		return listingPanel.getFieldPanel().getViewerPosition();
	}

	public void setViewerPosition(ViewerPosition position) {
		listingPanel.getFieldPanel().setViewerPosition(position.getIndex(), position.getXOffset(),
			position.getYOffset());
	}

	public void setMouseNavigationEnabled(boolean enabled) {
		listingPanel.removeButtonPressedListener(fieldNavigator);
		if (enabled) {
			listingPanel.addButtonPressedListener(new FieldNavigator(serviceProvider, null));
		}
	}

	@Override
	public void listingDiffChanged() {
		updateFunctionComparisonDiffHighlights();
		setUnmatchedCodeUnitAreaMarkers();
		setDiffAreaMarkers();
	}

	private void updateFunctionComparisonDiffHighlights() {
		setDiffHighlightProvider(
			new ListingDiffHighlightProvider(listingDiff, side, comparisonOptions));
	}

	private void setDiffAreaMarkers() {
		Color color = comparisonOptions.getDiffCodeUnitsBackgroundColor();
		AddressSetView addresses = listingDiff.getDiffs(side);

		setAreaMarkers(diffMarkers, addresses, color);
	}

	private void setUnmatchedCodeUnitAreaMarkers() {
		Color color = comparisonOptions.getUnmatchedCodeUnitsBackgroundColor();
		AddressSetView addresses = listingDiff.getUnmatchedCode(side);
		setAreaMarkers(unmatchedMarkers, addresses, color);
	}

}
