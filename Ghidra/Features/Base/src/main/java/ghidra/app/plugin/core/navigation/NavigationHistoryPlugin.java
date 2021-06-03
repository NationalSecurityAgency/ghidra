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
package ghidra.app.plugin.core.navigation;

import java.util.*;

import org.jdom.Element;

import docking.ComponentProvider;
import docking.DockingWindowManager;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.nav.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.bean.opteditor.OptionsVetoException;

/**
 * <CODE>NavigationHistoryPlugin</CODE> is used in conjunction with other
 * plugins to cause program viewer plugins to change their focus to a certain
 * address. As viewer plugins are directed to one or more addresses it maintains
 * information about where the viewers have been to support ability for the
 * viewers to go back to a previous "focus" point.
 * 
 * Services Provided: NavigationHistoryService
 * Events Consumed: ProgramLocationPluginEvent, ProgramPluginEvent 
 * Event Produced: HistoryChangePluginEvent Actions: None.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Tool State History",
	description = "This plugin maintains a history of tool states. "
			+ "It is used in conjunction with other plugins "
			+ "to cause program viewer plugins to change their focus to a certain address. "
			+ "As viewer plugins are directed to one or more addresses, it maintains "
			+ "information about where the viewers have been to support ability for the viewers "
			+ "to go back to a previous \"focus\" point.",
	servicesRequired = { ProgramManager.class },
	servicesProvided = { NavigationHistoryService.class },
	eventsConsumed = { ProgramClosedPluginEvent.class }
)
//@formatter:on
public class NavigationHistoryPlugin extends Plugin
		implements NavigationHistoryService, NavigatableRemovalListener, OptionsChangeListener {

	private static final String MAX_NAVIGATION_HISTORY_SIZE_OPTION_NAME =
		"Max Navigation History Size";
	private static final String HISTORY_LIST = "HISTORY_LIST_";
	private static final String LIST_COUNT = "LIST_COUNT";
	private static final String LOCATION_COUNT = "LOCATION_COUNT";
	private static final String NAV_ID = "NAV_ID";
	private static final String CURRENT_LOCATION_INDEX = "CURRENT_LOC_INDEX";
	private static final String MEMENTO_DATA = "MEMENTO_DATA";
	private static final String MEMENTO_CLASS = "MEMENTO_CLASS";

	private Map<Navigatable, HistoryList> historyListMap = new HashMap<>();
	private static final int ABSOLUTE_MAX_HISTORY_SIZE = 100;
	private static final int ABSOLUTE_MIN_HISTORY_SIZE = 10;
	final static int MAX_HISTORY_SIZE = 30;
	private int maxHistorySize = MAX_HISTORY_SIZE;

	private SaveState dataSaveState;

	public NavigationHistoryPlugin(PluginTool tool) {
		super(tool);
		tool.getOptions(ToolConstants.TOOL_OPTIONS);
	}

	@Override
	protected void dispose() {
		ToolOptions options = tool.getOptions(ToolConstants.TOOL_OPTIONS);
		options.removeOptionsChangeListener(this);

		super.dispose();
	}

	@Override
	protected void init() {
		initOptions();
	}

	@Override
	public void readDataState(SaveState saveState) {
		this.dataSaveState = saveState;
	}

	@Override
	public void dataStateRestoreCompleted() {
		if (dataSaveState == null) {
			return;
		}
		ProgramManager pm = tool.getService(ProgramManager.class);
		Program[] programs = pm.getAllOpenPrograms();
		int count = dataSaveState.getInt(LIST_COUNT, 0);
		for (int i = 0; i < count; i++) {
			Element xmlElement = dataSaveState.getXmlElement(HISTORY_LIST + i);
			restoreHistoryList(xmlElement, programs);
		}
		dataSaveState = null;
		notifyHistoryChange();
	}

	private void initOptions() {
		ToolOptions options = tool.getOptions(ToolConstants.TOOL_OPTIONS);

		options.registerOption(MAX_NAVIGATION_HISTORY_SIZE_OPTION_NAME, MAX_HISTORY_SIZE, null,
			"The maximum number of items to display in the tool's navigation history.");
		maxHistorySize = options.getInt(MAX_NAVIGATION_HISTORY_SIZE_OPTION_NAME, MAX_HISTORY_SIZE);

		options.addOptionsChangeListener(this);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (MAX_NAVIGATION_HISTORY_SIZE_OPTION_NAME.equals(optionName)) {
			int newMaxHistorySize =
				options.getInt(MAX_NAVIGATION_HISTORY_SIZE_OPTION_NAME, MAX_HISTORY_SIZE);
			if (newMaxHistorySize > ABSOLUTE_MAX_HISTORY_SIZE) {
				throw new OptionsVetoException(
					"History size cannot be greater than " + ABSOLUTE_MAX_HISTORY_SIZE);
			}
			if (newMaxHistorySize < ABSOLUTE_MIN_HISTORY_SIZE) {
				throw new OptionsVetoException(
					"History size cannot be less than " + ABSOLUTE_MIN_HISTORY_SIZE);
			}
			maxHistorySize = newMaxHistorySize;

			updateHistoryListMaxSize(maxHistorySize);
		}
	}

	private void updateHistoryListMaxSize(int maxLocations) {
		Collection<HistoryList> historyLists = historyListMap.values();
		for (HistoryList historyList : historyLists) {
			historyList.setMaxLocations(maxLocations);
		}
	}

	private void restoreHistoryList(Element xmlElement, Program[] programs) {
		SaveState saveState = new SaveState(xmlElement);
		Navigatable nav = NavigatableRegistry.getNavigatable(saveState.getLong(NAV_ID, 0));
		if (nav == null) {
			return;
		}
		nav.addNavigatableListener(this);
		HistoryList historyList = new HistoryList(maxHistorySize);
		historyListMap.put(nav, historyList);

		int count = saveState.getInt(LOCATION_COUNT, 0);
		for (int i = 0; i < count; i++) {
			LocationMemento memento = restoreLocation(i, saveState, programs);
			if (memento != null) {
				historyList.addLocation(memento);
			}
		}
		int currentLocationIndex = saveState.getInt(CURRENT_LOCATION_INDEX, historyList.size());
		historyList.setCurrentLocationIndex(currentLocationIndex);
	}

	@Override
	public void writeDataState(SaveState saveState) {
		int count = 0;
		for (Navigatable navigatable : historyListMap.keySet()) {
			HistoryList historyList = historyListMap.get(navigatable);
			SaveState listSaveState = new SaveState();
			writeDataState(listSaveState, navigatable, historyList);
			saveState.putXmlElement(HISTORY_LIST + count, listSaveState.saveToXml());
			count++;
		}
		saveState.putInt(LIST_COUNT, count);
	}

	public void writeDataState(SaveState saveState, Navigatable navigatable,
			HistoryList historyList) {
		saveState.putLong(NAV_ID, navigatable.getInstanceID());
		saveState.putInt(LOCATION_COUNT, historyList.size());
		saveState.putInt(CURRENT_LOCATION_INDEX, historyList.getCurrentLocationIndex());
		for (int i = 0; i < historyList.size(); i++) {
			LocationMemento location = historyList.getLocation(i);
			saveLocation(i, saveState, location);
		}
	}

	@Override
	public void nextFunction(Navigatable navigatable) {
		if (hasNextFunction(navigatable)) {
			HistoryList historyList = historyListMap.get(navigatable);
			LocationMemento memento = historyList.nextFunction(navigatable, true);
			navigate(navigatable, memento);
		}
	}

	@Override
	public void previousFunction(Navigatable navigatable) {
		if (hasPreviousFunction(navigatable)) {
			HistoryList historyList = historyListMap.get(navigatable);
			addCurrentLocationToHistoryIfAppropriate(navigatable, historyList.getCurrentLocation());
			LocationMemento memento = historyList.previousFunction(navigatable, true);
			navigate(navigatable, memento);
		}
	}

	@Override
	public boolean hasNextFunction(Navigatable navigatable) {
		HistoryList historyList = historyListMap.get(navigatable);
		return historyList != null && historyList.hasNextFunction(navigatable);
	}

	@Override
	public boolean hasPreviousFunction(Navigatable navigatable) {
		HistoryList historyList = historyListMap.get(navigatable);
		return historyList != null && historyList.hasPreviousFunction(navigatable);
	}

	@Override
	public void next(Navigatable navigatable) {
		if (hasNext(navigatable)) {
			HistoryList historyList = historyListMap.get(navigatable);
			LocationMemento nextLocation = historyList.next();
			navigate(navigatable, nextLocation);
		}
	}

	@Override
	public void previous(Navigatable navigatable) {
		if (hasPrevious(navigatable)) {
			HistoryList historyList = historyListMap.get(navigatable);
			addCurrentLocationToHistoryIfAppropriate(navigatable, historyList.getCurrentLocation());

			LocationMemento previousLocation = historyList.previous();
			navigate(navigatable, previousLocation);
		}
	}

	private void addCurrentLocationToHistoryIfAppropriate(Navigatable navigatable,
			LocationMemento location) {
		if (!hasNext(navigatable)) {
			HistoryList historyList = historyListMap.get(navigatable);
			LocationMemento currentLocation = navigatable.getMemento();
			if (currentLocation.isValid()) {
				historyList.addLocation(currentLocation);
			}
		}
	}

	@Override
	public void next(Navigatable navigatable, LocationMemento location) {
		while (hasNext(navigatable)) {
			HistoryList historyList = historyListMap.get(navigatable);
			LocationMemento nextLocation = historyList.next();
			if (nextLocation == location) {
				navigate(navigatable, nextLocation);
				break;
			}
		}
	}

	private void navigate(Navigatable navigatable, LocationMemento memento) {
		if (memento == null) {
			return;
		}

		navigatable.goTo(memento.getProgram(), memento.getProgramLocation());
		navigatable.setMemento(memento);
		if (navigatable.isVisible()) {
			navigatable.requestFocus();
		}
		tool.contextChanged(null);
	}

	@Override
	public void previous(Navigatable navigatable, LocationMemento location) {
		addCurrentLocationToHistoryIfAppropriate(navigatable, location);
		while (hasPrevious(navigatable)) {
			HistoryList historyList = historyListMap.get(navigatable);
			LocationMemento previousLocation = historyList.previous();
			if (previousLocation == location) {
				navigate(navigatable, previousLocation);
				break;
			}
		}
	}

	@Override
	public List<LocationMemento> getNextLocations(Navigatable navigatable) {
		HistoryList historyList = historyListMap.get(navigatable);
		if (historyList != null) {
			return historyList.getNextLocations();
		}
		return new ArrayList<>();
	}

	@Override
	public List<LocationMemento> getPreviousLocations(Navigatable navigatable) {
		HistoryList historyList = historyListMap.get(navigatable);
		if (historyList == null) {
			return new ArrayList<>();
		}
		List<LocationMemento> previousLocations = historyList.getPreviousLocations();
		if (!hasNext(navigatable)) {
			LocationMemento currentHistoryLocation = historyList.getCurrentLocation();
			LocationMemento currentLocation = navigatable.getMemento();
			if (!currentLocation.equals(currentHistoryLocation)) {
				previousLocations.add(0, currentHistoryLocation);
			}
		}
		return previousLocations;
	}

	@Override
	public boolean hasNext(Navigatable navigatable) {
		HistoryList historyList = historyListMap.get(navigatable);
		return historyList != null && historyList.hasNext();
	}

	@Override
	public boolean hasPrevious(Navigatable navigatable) {
		HistoryList historyList = historyListMap.get(navigatable);
		return historyList != null && historyList.hasPrevious();
	}

	@Override
	public void clear(Navigatable navigatable) {
		historyListMap.remove(navigatable);
		notifyHistoryChange();
	}

	private void clear(Program program) {
		for (HistoryList historyList : historyListMap.values()) {
			clear(historyList, program);
		}
		notifyHistoryChange();
	}

	private void clear(HistoryList historyList, Program program) {
		for (int i = historyList.size() - 1; i >= 0; i--) {
			LocationMemento location = historyList.getLocation(i);
			if (location.getProgram() == program) {
				historyList.remove(location);
			}
		}
	}

	private void notifyHistoryChange() {
		tool.contextChanged(null);
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramClosedPluginEvent) {
			clear(((ProgramClosedPluginEvent) event).getProgram());
		}
	}

	@Override
	public void addNewLocation(Navigatable navigatable) {
		navigatable = getHistoryNavigatable(navigatable);
		HistoryList historyList = historyListMap.get(navigatable);
		if (historyList == null) {
			navigatable.addNavigatableListener(this);
			historyList = new HistoryList(maxHistorySize);
			historyListMap.put(navigatable, historyList);
		}

		LocationMemento memento = navigatable.getMemento();
		if (memento.isValid()) {
			historyList.addLocation(memento);
			notifyHistoryChange();
		}
	}

	private Navigatable getHistoryNavigatable(Navigatable navigatable) {
		if (!navigatable.isConnected()) {
			return navigatable;
		}

		GoToService service = tool.getService(GoToService.class);
		if (service != null) {
			return service.getDefaultNavigatable();
		}
		return null;
	}

	@Override
	public void navigatableRemoved(Navigatable navigatable) {
		navigatable.removeNavigatableListener(this);
		clear(navigatable);
	}

	private void saveLocation(int index, SaveState saveState, LocationMemento memento) {
		SaveState mementoSaveState = new SaveState();
		memento.saveState(mementoSaveState);
		Element element = mementoSaveState.saveToXml();
		saveState.putString(MEMENTO_CLASS + index, memento.getClass().getName());
		saveState.putXmlElement(MEMENTO_DATA + index, element);
	}

	private LocationMemento restoreLocation(int index, SaveState saveState, Program[] programs) {
		Element mementoElement = saveState.getXmlElement(MEMENTO_DATA + index);
		if (mementoElement == null) {
			return null;
		}

		SaveState mementoState = new SaveState(mementoElement);
		LocationMemento locationMemento = null;
		try {
			locationMemento = LocationMemento.getLocationMemento(mementoState, programs);
		}
		catch (IllegalArgumentException iae) {
			// this can happen if a program is renamed or deleted but the tool config state
			// has not been saved since the delete
			Msg.trace(this, "Unable to restore LocationMemento: " + iae.getMessage(), iae);
		}
		return locationMemento;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================    

	private static class HistoryList {
		private List<LocationMemento> list = new ArrayList<>();
		private int currentLocation = 0;
		private int maxLocations;

		HistoryList(int maxLocations) {
			this.maxLocations = maxLocations;
		}

		int getCurrentLocationIndex() {
			return currentLocation;
		}

		void setCurrentLocationIndex(int index) {
			if (index >= 0 && index < list.size()) {
				currentLocation = index;
			}
		}

		int size() {
			return list.size();
		}

		LocationMemento getLocation(int index) {
			return list.get(index);
		}

		LocationMemento getCurrentLocation() {
			return list.get(currentLocation);
		}

		void addLocation(LocationMemento newValue) {
			if (list.isEmpty()) {
				list.add(newValue);
				currentLocation = 0;
				return;
			}

			while (list.size() - 1 > currentLocation) {
				list.remove(list.size() - 1);
			}

			LocationMemento lastLocation = list.get(list.size() - 1);
			if (!newValue.equals(lastLocation)) {
				list.add(newValue); // new location, add it to list
			}
			else {
				// same location, but maybe different "extra" info replace equivalent location
				list.set(list.size() - 1, newValue);
			}

			if (list.size() > maxLocations) {
				list.remove(0);
			}
			currentLocation = list.size() - 1;
		}

		void setMaxLocations(int maxLocations) {
			this.maxLocations = maxLocations;
		}

		boolean hasNext() {
			if (list.isEmpty()) {
				return false;
			}
			return currentLocation < list.size() - 1;
		}

		boolean hasPrevious() {
			if (list.isEmpty()) {
				return false;
			}
			return currentLocation > 0;
		}

		LocationMemento next() {
			if (hasNext()) {
				currentLocation++;
				return list.get(currentLocation);
			}
			return null;
		}

		LocationMemento previous() {
			if (hasPrevious()) {
				currentLocation--;
				return list.get(currentLocation);
			}
			return null;
		}

		boolean hasNextFunction(Navigatable navigatable) {
			return nextFunction(navigatable, false) != null;
		}

		boolean hasPreviousFunction(Navigatable navigatable) {
			return previousFunction(navigatable, false) != null;
		}

		/**
		 * Find the next history LocationMemento that contains a different function.  If no such
		 * LocationMemento is found, null is returned.
		 * 
		 * @param navigatable the navigatable being navigated
		 * @param moveTo true means after finding, get current location to it. false to just find 
		 * 			and do nothing
		 * @return next LocationMemento, or null if no next function
		 */
		private LocationMemento nextFunction(Navigatable navigatable, boolean moveTo) {

			if (list.isEmpty()) {
				return null;
			}

			Function currentFunction = getCurrentFunction(navigatable);

			for (int i = currentLocation + 1; i < list.size(); i++) {
				LocationMemento memento = list.get(i);
				ProgramLocation otherLocation = memento.getProgramLocation();
				Address address = otherLocation.getAddress();
				FunctionManager functionManager = otherLocation.getProgram().getFunctionManager();
				Function historyFunction = functionManager.getFunctionContaining(address);
				if (historyFunction != null && !historyFunction.equals(currentFunction)) {
					if (moveTo) {
						currentLocation = i;
					}
					return memento;
				}
			}

			return null;
		}

		private Function getCurrentFunction(Navigatable navigatable) {
			ProgramLocation location = navigatable.getLocation();
			if (location == null) {
				return null;
			}
			Program program = location.getProgram();
			FunctionManager functionManager = program.getFunctionManager();
			return functionManager.getFunctionContaining(location.getAddress());
		}

		/**
		 * Find the previous history LocationMemento that contains a different function. If no such
		 * LocationMemento is found, null is returned.
		 * 
		 * @param navigatable the navigatable being navigated
		 * @param moveTo true means after finding, get current location to it. false to just find 
		 * 		   and do nothing
		 * @return previous LocationMemento, or null if no previous function found
		 */
		private LocationMemento previousFunction(Navigatable navigatable, boolean moveTo) {
			if (list.isEmpty()) {
				return null;
			}

			Function startFunction = getPreviousStartFunction(navigatable);
			for (int i = currentLocation - 1; i >= 0; i--) {

				LocationMemento memento = list.get(i);
				ProgramLocation otherLocation = memento.getProgramLocation();
				Address address = otherLocation.getAddress();
				FunctionManager functionManager = otherLocation.getProgram().getFunctionManager();
				Function historyFunction = functionManager.getFunctionContaining(address);

				if (historyFunction != null && !historyFunction.equals(startFunction)) {
					if (moveTo) {
						currentLocation = i;
					}
					return memento;
				}
			}

			return null;
		}

		private Function getPreviousStartFunction(Navigatable navigatable) {
			ProgramLocation location = navigatable.getLocation();
			if (location == null) {
				return null;
			}

			Address currentAddress = location.getAddress();

			//
			// The active component may still be showing the previously loaded function, instead
			// of the current location when that location is not in a function.  In that case, 
			// when that provider is focused, prefer its notion of the current function so that
			// users navigating from that view will go to the function before the one that is
			// on the history stack.  This should feel more intuitive to the user, with the risk
			// that the navigation actions will sometimes feel inconsistent, depending upon
			// what view is focused.
			//
			DockingWindowManager manager = DockingWindowManager.getActiveInstance();
			ComponentProvider provider = manager.getActiveComponentProvider();
			if (provider instanceof Navigatable) {
				LocationMemento memento = ((Navigatable) provider).getMemento();
				ProgramLocation otherLocation = memento.getProgramLocation();
				if (otherLocation != null) {
					currentAddress = otherLocation.getAddress();
				}
			}

			Program program = location.getProgram();
			FunctionManager functionManager = program.getFunctionManager();
			return functionManager.getFunctionContaining(currentAddress);
		}

		void remove(LocationMemento location) {
			for (int i = 0; i < list.size(); i++) {
				LocationMemento loc = list.get(i);
				if (loc.equals(location)) {
					list.remove(i);
					if (currentLocation > 0 && currentLocation >= i) {
						currentLocation--;
					}
					return;
				}
			}
		}

		List<LocationMemento> getPreviousLocations() {
			List<LocationMemento> previousLocations = new ArrayList<>();
			for (int i = 0; i < currentLocation; i++) {
				previousLocations.add(list.get(i));
			}
			Collections.reverse(previousLocations);
			return previousLocations;
		}

		List<LocationMemento> getNextLocations() {
			List<LocationMemento> nextLocations = new ArrayList<>();
			for (int i = currentLocation + 1; i < list.size(); i++) {
				nextLocations.add(list.get(i));
			}
			return nextLocations;
		}
	}

}
