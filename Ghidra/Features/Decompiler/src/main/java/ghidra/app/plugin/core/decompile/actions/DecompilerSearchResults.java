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
package ghidra.app.plugin.core.decompile.actions;

import java.time.Duration;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import docking.widgets.SearchLocation;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.search.SearchResults;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.worker.Worker;

public class DecompilerSearchResults extends SearchResults {

	// the location when the search was performed; used to know when the function has changed
	private ProgramLocation programLocation;
	private DecompilerPanel decompilerPanel;
	private String searchText;
	private List<SearchLocation> searchLocations;
	private Map<Integer, List<DecompilerSearchLocation>> locationsByLine;
	private TreeMap<LinePosition, DecompilerSearchLocation> matchesByPosition = new TreeMap<>();

	private DecompilerSearchLocation activeLocation;

	DecompilerSearchResults(Worker worker, DecompilerPanel decompilerPanel, String searchText,
			List<SearchLocation> searchLocations) {
		super(worker);
		this.decompilerPanel = decompilerPanel;
		this.searchText = searchText;

		this.searchLocations = searchLocations;
		this.programLocation = decompilerPanel.getCurrentLocation();

		for (SearchLocation location : searchLocations) {
			int line = location.getLineNumber();
			int col = location.getStartIndexInclusive();
			LinePosition lp = new LinePosition(line, col);
			DecompilerSearchLocation dsl = (DecompilerSearchLocation) location;
			matchesByPosition.put(lp, dsl);
		}
	}

	@Override
	public String getName() {
		DecompilerController controller = decompilerPanel.getController();
		Function function = controller.getFunction();
		return function.getName() + "()";
	}

	ProgramLocation getDecompileLocation() {
		return programLocation;
	}

	boolean isInvalid(String otherSearchText) {
		if (isDifferentFunction()) {
			return true;
		}
		return !searchText.equals(otherSearchText);
	}

	@Override
	public boolean isEmpty() {
		return searchLocations.isEmpty();
	}

	@Override
	public List<SearchLocation> getLocations() {
		return searchLocations;
	}

	public Map<Integer, List<DecompilerSearchLocation>> getLocationsByLine() {
		if (locationsByLine == null) {
			locationsByLine = searchLocations.stream()
					.map(l -> (DecompilerSearchLocation) l)
					.collect(Collectors.groupingBy(l -> l.getLineNumber()));
		}
		return locationsByLine;
	}

	private boolean isDifferentFunction() {
		return !decompilerPanel.containsLocation(programLocation);
	}

	private boolean isMyFunction() {
		return decompilerPanel.containsLocation(programLocation);
	}

	public DecompilerSearchLocation getContainingLocation(FieldLocation fieldLocation,
			boolean searchForward) {

		// getNextLocation() will find the next matching location, starting at the given field
		// location.  The next location may or may not actually contain the given field location.
		DecompilerSearchLocation nextLocation = getNextLocation(fieldLocation, searchForward);
		if (nextLocation.contains(fieldLocation)) {
			return nextLocation;
		}
		return null;
	}

	@Override
	public DecompilerSearchLocation getActiveLocation() {
		return activeLocation;
	}

	private void installSearchResults() {
		if (isDifferentFunction()) {
			return; // a different function was decompiled while we were running
		}
		decompilerPanel.setSearchResults(this);
	}

	private void clearSearchResults() {
		decompilerPanel.clearSearchResults(this);
	}

	public void decompilerUpdated() {
		// The decompiler has updated.  It may have been upon our request.  If not, deactivate.
		if (isDifferentFunction()) {
			deactivate();
		}
	}

	@Override
	public void deactivate() {
		FindJob job = new SwingJob(this::clearSearchResults);
		runJob(job);
	}

	@Override
	public void activate() {
		FindJob job = createActivationJob().thenRunSwing(this::installSearchResults);
		runJob(job);
	}

	@Override
	public void setActiveLocation(SearchLocation location) {

		if (activeLocation == location) {
			return;
		}

		activeLocation = (DecompilerSearchLocation) location;
		if (location == null) {
			return;
		}

		// activate() will set the active search location
		activate();
	}

	private ActivationJob createActivationJob() {
		if (isMyFunction()) {
			return createFinishedActivationJob(); // nothing to do
		}

		return (ActivationJob) new ActivateFunctionJob()
				.thenWait(this::isMyFunction, Duration.ofSeconds(5));
	}

	protected ActivationJob createFinishedActivationJob() {
		return new ActivationJob();
	}

	@Override
	public void dispose() {
		setActiveLocation(null);
		decompilerPanel.clearSearchResults(this);
		searchLocations.clear();
	}

	DecompilerSearchLocation getNextLocation(FieldLocation startLocation,
			boolean searchForward) {

		Entry<LinePosition, DecompilerSearchLocation> entry;
		int line = startLocation.getIndex().intValue() + 1; // +1 for zero based
		int col = startLocation.getCol();
		LinePosition lp = new LinePosition(line, col);
		if (searchForward) {
			entry = matchesByPosition.ceilingEntry(lp);
		}
		else {
			entry = matchesByPosition.floorEntry(lp);
		}

		if (entry == null) {
			return null; // no more matches in the current direction
		}

		return entry.getValue();
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

	private class ActivateFunctionJob extends ActivationJob {
		@Override
		protected void doRun(TaskMonitor monitor) throws CancelledException {
			if (isMyFunction()) {
				return; // nothing to do
			}

			DecompilerController controller = decompilerPanel.getController();
			Program program = programLocation.getProgram();
			controller.refreshDisplay(program, programLocation, null);
		}
	}

	private record LinePosition(int line, int col) implements Comparable<LinePosition> {

		@Override
		public int compareTo(LinePosition other) {

			int result = line - other.line;
			if (result != 0) {
				return result;
			}

			return col - other.col;
		}
	}

}
