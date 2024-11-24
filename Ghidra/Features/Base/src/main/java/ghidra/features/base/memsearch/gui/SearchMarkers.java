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
package ghidra.features.base.memsearch.gui;

import java.util.List;

import javax.swing.Icon;

import generic.theme.GIcon;
import ghidra.app.services.*;
import ghidra.app.util.SearchConstants;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;

/**
 * Manages the {@link MarkerSet} for a given {@link MemorySearchProvider} window.
 */
public class SearchMarkers {
	private static final Icon SEARCH_MARKER_ICON = new GIcon("icon.base.search.marker");
	private MarkerService service;
	private MarkerSet markerSet;
	private Program program;

	public SearchMarkers(PluginTool tool, String title, Program program) {
		this.program = program;
		service = tool.getService(MarkerService.class);
		if (service == null) {
			return;
		}
	}

	private MarkerSet createMarkerSet(String title) {
		MarkerSet markers = service.createPointMarker(title, "Search", program,
			MarkerService.SEARCH_PRIORITY, true, true, false,
			SearchConstants.SEARCH_HIGHLIGHT_COLOR, SEARCH_MARKER_ICON);

		markers.setMarkerDescriptor(new MarkerDescriptor() {
			@Override
			public ProgramLocation getProgramLocation(MarkerLocation loc) {
				return new BytesFieldLocation(program, loc.getAddr());
			}
		});

		// remove it; we will add it later to a group
		service.removeMarker(markers, program);
		return markers;
	}

	void makeActiveMarkerSet() {
		if (service == null || markerSet == null) {
			return;
		}
		service.setMarkerForGroup(MarkerService.HIGHLIGHT_GROUP, markerSet, program);
	}

	void loadMarkers(String title, List<MemoryMatch> matches) {
		if (service == null) {
			return;
		}

		if (matches.isEmpty()) {
			deleteMarkerSet();
			return;
		}

		// If the title of the provider changes, we need to re-create the marker set as the 
		// provider's title is what is used as the marker set's name. The name is what shows up in
		// the marker set gui for turning markers on and off - if they don't match the provider's
		// title, it isn't obvious what provider the markers represent. (And currently, there is
		// no way to change a marker set's name once it is created.)
		if (markerSet != null && !markerSet.getName().equals(title)) {
			deleteMarkerSet();
		}

		if (markerSet == null) {
			markerSet = createMarkerSet(title);
		}

		markerSet.clearAll();
		for (MemoryMatch match : matches) {
			markerSet.add(match.getAddress());
		}
		service.setMarkerForGroup(MarkerService.HIGHLIGHT_GROUP, markerSet, program);
	}

	private void deleteMarkerSet() {
		if (markerSet != null) {
			markerSet.clearAll();
			service.removeMarker(markerSet, program);
			markerSet = null;
		}
	}

	public void dispose() {
		deleteMarkerSet();
		program = null;
	}
}
