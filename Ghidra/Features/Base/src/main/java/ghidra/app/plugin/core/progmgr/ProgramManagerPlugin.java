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
package ghidra.app.plugin.core.progmgr;

import java.beans.PropertyEditor;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.options.editor.*;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.progmgr.MultiProgramManager.ProgramInfo;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.task.OpenProgramRequest;
import ghidra.app.util.task.OpenProgramTask;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.OpenVersionedFileDialog;
import ghidra.framework.model.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskLauncher;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Manage open programs",
	description = "This plugin provides actions for opening and closing programs.  It also " +
			"provides a service to allow plugins to open/close programs.  This plugin is " +
			"responsible for sending out plugin events to notify all other programs when a " +
			"program is opened or close.",
	servicesProvided = { ProgramManager.class },
	eventsConsumed = {
		OpenProgramPluginEvent.class, CloseProgramPluginEvent.class,
		ExternalProgramLocationPluginEvent.class, ExternalProgramSelectionPluginEvent.class,
		ProgramActivatedPluginEvent.class, ProgramLocationPluginEvent.class,
		ProgramSelectionPluginEvent.class },
	eventsProduced = {
		OpenProgramPluginEvent.class, CloseProgramPluginEvent.class,
		ExternalProgramLocationPluginEvent.class, ExternalProgramSelectionPluginEvent.class,
		ProgramOpenedPluginEvent.class, ProgramClosedPluginEvent.class,
		ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class ProgramManagerPlugin extends Plugin implements ProgramManager, OptionsChangeListener {
	private final static String CACHE_DURATION_OPTION =
		"Program Cache.Program Cache Time (minutes)";
	private final static String CACHE_SIZE_OPTION = "Program Cache.Program Cache Size";
	private static final int DEFAULT_PROGRAM_CACHE_CAPACITY = 50;
	private static final int DEFAULT_PROGRAM_CACHE_DURATION = 30; // in minutes

	private static final String SAVE_GROUP = "DomainObjectSave";
	static final String OPEN_GROUP = "DomainObjectOpen";
	private MultiProgramManager programMgr;
	private ProgramCache programCache;
	private ProgramSaveManager programSaveMgr;
	private int transactionID = -1;
	private UndoAction undoAction;
	private RedoAction redoAction;
	private ProgramLocation currentLocation;

	public ProgramManagerPlugin(PluginTool tool) {
		super(tool);

		createActions();
		programMgr = new MultiProgramManager(this);
		programCache = new ProgramCache(Duration.ofMinutes(DEFAULT_PROGRAM_CACHE_DURATION),
			DEFAULT_PROGRAM_CACHE_CAPACITY);
		programSaveMgr = new ProgramSaveManager(tool, this);
		initializeOptions(tool.getOptions("Tool"));
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(CACHE_DURATION_OPTION)) {
			Duration duration = Duration.ofMinutes((int) newValue);
			programCache.setDuration(duration);
		}
		if (optionName.equals(CACHE_SIZE_OPTION)) {
			int capacity = (int) newValue;
			programCache.setCapacity(capacity);
		}
	}

	private void initializeOptions(ToolOptions options) {
		HelpLocation helpLocation =
			new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Program_Cache_Duration");
		options.registerOption(CACHE_DURATION_OPTION, DEFAULT_PROGRAM_CACHE_DURATION, helpLocation,
			"Sets the time (in minutes) cached programs are kept around before closing");
		helpLocation = new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Program_Cache_Size");
		options.registerOption(CACHE_SIZE_OPTION, DEFAULT_PROGRAM_CACHE_CAPACITY, helpLocation,
			"Sets the maximum number of programs to be cached");

		int duration = options.getInt(CACHE_DURATION_OPTION, DEFAULT_PROGRAM_CACHE_DURATION);
		int capacity = options.getInt(CACHE_SIZE_OPTION, DEFAULT_PROGRAM_CACHE_CAPACITY);
		programCache.setCapacity(capacity);
		programCache.setDuration(Duration.ofMinutes(duration));
		options.addOptionsChangeListener(this);
	}

	/**
	 * Method called if the plugin supports this domain file.
	 *
	 * @param data the data to be used by the running tool
	 * @return false if data is not a Program object.
	 */
	@Override
	public boolean acceptData(DomainFile[] data) {
		if (data == null || data.length == 0) {
			return false;
		}

		List<DomainFile> filesToOpen = new ArrayList<>();
		for (DomainFile domainFile : data) {
			if (domainFile == null) {
				continue;
			}
			Class<? extends DomainObject> domainObjectClass = domainFile.getDomainObjectClass();
			if (Program.class.isAssignableFrom(domainObjectClass)) {
				filesToOpen.add(domainFile);
			}
		}
		openPrograms(filesToOpen);

		return !filesToOpen.isEmpty();
	}

	@Override
	public boolean accept(URL url) {
		return openProgram(url, OPEN_CURRENT) != null;
	}

	@Override
	public Class<?>[] getSupportedDataTypes() {
		return new Class[] { Program.class };
	}

	@Override
	public Program openProgram(DomainFile df) {
		return openProgram(df, DomainFile.DEFAULT_VERSION, OPEN_CURRENT);
	}

	@Override
	public Program openProgram(DomainFile df, int version) {
		return openProgram(df, version, OPEN_CURRENT);
	}

	@Override
	public Program openProgram(DomainFile domainFile, int version, int state) {
		return openProgram(new ProgramLocator(domainFile, version), state);
	}

	@Override
	public Program openProgram(URL ghidraURL, int state) {
		String location = ghidraURL.getRef();
		Program program = openProgram(new ProgramLocator(ghidraURL), state);

		if (program != null && location != null && state == OPEN_CURRENT) {
			gotoProgramRef(program, ghidraURL.getRef());
			programMgr.saveLocation();
		}
		return program;
	}

	private Program openProgram(ProgramLocator locator, int state) {
		Program program = Swing.runNow(() -> {
			return doOpenProgramSwing(locator, state);
		});
		if (program != null) {
			Msg.info(this, "Opened program in " + tool.getName() + " tool: " + locator);
		}
		return program;
	}

	private Program doOpenProgramSwing(ProgramLocator locator, int state) {
		// see if already open
		Program program = programMgr.getOpenProgram(locator);
		if (program != null) {
			showProgram(program, locator, state);
			return program;
		}

		// see if cached
		program = programCache.get(locator);
		if (program != null) {
			programMgr.addProgram(program, locator, state);
			return program;
		}

		// ok, then open it
		OpenProgramTask task = new OpenProgramTask(locator, this);
		new TaskLauncher(task, tool.getToolFrame());
		OpenProgramRequest request = task.getOpenProgram();
		if (request != null) {
			program = request.getProgram();
			programMgr.addProgram(program, locator, state);
			request.release();
			return program;
		}
		return null;
	}

	private boolean gotoProgramRef(Program program, String ref) {
		if (StringUtils.isBlank(ref)) {
			return false;
		}

		String trimmedRef = ref.trim();
		ProgramLocation loc = getLocationForSymbolRef(program, trimmedRef);
		if (loc == null) {
			loc = getLocationForAddressRef(program, trimmedRef);
		}

		if (loc == null) {
			Msg.showError(this, null, "Navigation Failed",
				"Referenced label/function not found: " + trimmedRef);
			return false;
		}

		firePluginEvent(new ProgramLocationPluginEvent(getName(), loc, program));
		return true;
	}

	private ProgramLocation getLocationForAddressRef(Program program, String ref) {
		Address addr = program.getAddressFactory().getAddress(ref);
		if (addr != null && addr.isMemoryAddress()) {
			return new CodeUnitLocation(program, addr, 0, 0, 0);
		}
		return null;
	}

	private ProgramLocation getLocationForSymbolRef(Program program, String ref) {
		List<Symbol> symbols = NamespaceUtils.getSymbols(ref, program);
		if (symbols.isEmpty()) {
			return null;
		}

		Symbol symbol = symbols.get(0);
		if (symbol == null) {
			return null;
		}

		SymbolType type = symbol.getSymbolType();
		if (type == SymbolType.FUNCTION) {
			return new FunctionSignatureFieldLocation(program, symbol.getAddress());
		}

		if (type == SymbolType.LABEL) {
			return new LabelFieldLocation(symbol);
		}
		return null;
	}

	@Override
	public Program openCachedProgram(URL ghidraURL, Object consumer) {
		return openCachedProgram(new ProgramLocator(ghidraURL), consumer);
	}

	@Override
	public Program openCachedProgram(DomainFile domainFile, Object consumer) {
		return openCachedProgram(new ProgramLocator(domainFile), consumer);
	}

	private Program openCachedProgram(ProgramLocator locator, Object consumer) {
		Program program = programCache.get(locator);
		if (program != null) {
			program.addConsumer(consumer);
			return program;
		}

		program = programMgr.getOpenProgram(locator);
		if (program != null) {
			program.addConsumer(consumer);
			if (!program.isChanged() || ProgramUtilities.isChangedWithUpgradeOnly(program)) {
				// Don't put modified programs into the cache unless the only change
				// corresponds to an upgrade during its instantiation.
				programCache.put(locator, program);
			}
			return program;
		}

		OpenProgramTask task = new OpenProgramTask(locator, consumer);
		new TaskLauncher(task, tool.getToolFrame());
		OpenProgramRequest result = task.getOpenProgram();
		if (result == null) {
			return null;
		}
		program = result.getProgram();
		programCache.put(locator, program);
		return program;
	}

	@Override
	public Program getCurrentProgram() {
		return programMgr.getCurrentProgram();
	}

	@Override
	public DomainFile[] getData() {
		Program[] p = getAllOpenPrograms();
		DomainFile[] dfs = new DomainFile[p.length];
		for (int i = 0; i < dfs.length; i++) {
			dfs[i] = p[i].getDomainFile();
		}
		return dfs;
	}

	@Override
	public Program[] getAllOpenPrograms() {
		return programMgr.getAllPrograms().toArray(Program[]::new);
	}

	@Override
	public void dispose() {
		programCache.clear();
		programMgr.dispose();
		tool.clearLastEvents();
	}

	@Override
	public boolean closeOtherPrograms(boolean ignoreChanges) {
		List<Program> otherPrograms = programMgr.getOtherPrograms();
		Runnable r = () -> doCloseAllPrograms(otherPrograms, ignoreChanges);
		Swing.runNow(r);
		return programMgr.isEmpty();
	}

	@Override
	public boolean closeAllPrograms(boolean ignoreChanges) {
		List<Program> openPrograms = programMgr.getAllPrograms();
		Runnable r = () -> doCloseAllPrograms(openPrograms, ignoreChanges);
		Swing.runNow(r);
		return programMgr.isEmpty();
	}

	private void doCloseAllPrograms(List<Program> openPrograms, boolean ignoreChanges) {
		List<Program> toRemove = new ArrayList<>();
		Program currentProgram = programMgr.getCurrentProgram();
		for (Program p : openPrograms) {
			if (ignoreChanges) {
				toRemove.add(p);
				continue;
			}
			else if (p.isClosed()) {
				toRemove.add(p);
				continue;
			}

			if (!tool.canCloseDomainObject(p)) {
				// Running tasks.  Do we cancel all closing or continue?  For now, continue
				// closing what we can.
				continue;
			}

			if (!programSaveMgr.canClose(p)) {
				// Cancelled!  Any cancel means to cancel all--just abort.
				return;
			}

			toRemove.add(p);
		}

		// Don't remove currentProgram until last to prevent activation of other programs.
		if (toRemove.contains(currentProgram)) {
			toRemove.remove(currentProgram);
			toRemove.add(currentProgram);
		}

		for (Program program : toRemove) {
			programMgr.removeProgram(program);
		}
		contextChanged();
	}

	@Override
	public boolean closeProgram(Program program, boolean ignoreChanges) {
		if (program == null) {
			return false;
		}
		Runnable r = () -> {
			// Note: The tool.canCloseDomainObject() call must come before the
			// programSaveMgr.canClose() call since plugins may save changes to the program
			// so that they can close.
			if (ignoreChanges || program.isClosed() || programMgr.isPersistent(program) ||
				(tool.canCloseDomainObject(program) && programSaveMgr.canClose(program))) {
				programMgr.removeProgram(program);
				contextChanged();
			}
		};
		Swing.runNow(r);
		return !programMgr.contains(program);
	}

	@Override
	protected void close() {
		List<Program> programs = programMgr.getAllPrograms();
		if (programs.isEmpty()) {
			return;
		}
		// Don't remove currentProgram until last to prevent activation of other programs.
		Program currentProgram = getCurrentProgram();
		for (Program program : programs) {
			if (program != currentProgram) {
				programMgr.removeProgram(program);
			}
		}
		if (currentProgram != null) {
			programMgr.removeProgram(currentProgram);
		}
		contextChanged();
		tool.setSubTitle("");
		tool.clearLastEvents();
	}

	@Override
	public void setCurrentProgram(Program p) {
		Runnable r = () -> {
			programMgr.setCurrentProgram(p);
			contextChanged();
		};
		Swing.runNow(r);
	}

	@Override
	public Program getProgram(Address addr) {
		return programMgr.getProgram(addr);

	}

	/**
	 * This method notifies listening plugins that a programs has been added to the program manager.
	 * This is not used for actually opening a program from the database and will act strangely if
	 * given a closed Program object.
	 *
	 * @see ghidra.app.services.ProgramManager#openProgram(ghidra.program.model.listing.Program)
	 */
	@Override
	public void openProgram(Program program) {
		openProgram(program, OPEN_CURRENT);
	}

	@Override
	public void openProgram(final Program program, final int state) {
		showProgram(program, new ProgramLocator(program.getDomainFile()), state);
	}

	private void showProgram(Program p, ProgramLocator locator, final int state) {
		if (p == null || p.isClosed()) {
			throw new AssertException("Opened program required");
		}

		Runnable r = () -> {
			programMgr.addProgram(p, locator, state);
			if (state == ProgramManager.OPEN_CURRENT) {
				programMgr.saveLocation();
			}
			contextChanged();
		};
		Swing.runNow(r);
	}

	@Override
	public boolean closeProgram() {
		return closeProgram(getCurrentProgram(), false);
	}

	@Override
	protected boolean saveData() {
		boolean result = programSaveMgr.saveAll();
		contextChanged();
		return result;
	}

	@Override
	protected boolean hasUnsaveData() {
		Program[] allOpenPrograms = getAllOpenPrograms();
		for (Program program : allOpenPrograms) {
			if (program.isChanged()) {
				return true;
			}
		}
		return false;
	}

	private void createActions() {

		int subMenuGroup = 1;

		DockingAction openAction =
			new ActionBuilder("Open File", getName()).menuPath(ToolConstants.MENU_FILE, "&Open...")
					.menuGroup(OPEN_GROUP, Integer.toString(subMenuGroup++))
					.keyBinding("ctrl O")
					.onAction(c -> open())
					.buildAndInstall(tool);
		openAction.addToWindowWhen(ProgramActionContext.class);

		tool.addAction(new CloseProgramAction(this, OPEN_GROUP, subMenuGroup++));
		new ActionBuilder("Close Others", getName())
				.menuPath(ToolConstants.MENU_FILE, "Close &Others")
				.menuGroup(OPEN_GROUP, Integer.toString(subMenuGroup++))
				.enabled(false)
				.withContext(ProgramActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.enabledWhen(c -> programMgr.contains(c.getProgram()))
				.onAction(c -> closeOtherPrograms(false))
				.buildAndInstall(tool);

		DockingAction closeAllAction = new ActionBuilder("Close All", getName())
				.menuPath(ToolConstants.MENU_FILE, "Close &All")
				.menuGroup(OPEN_GROUP, Integer.toString(subMenuGroup++))
				.enabledWhen(c -> !programMgr.isEmpty())
				.onAction(c -> closeAllPrograms(false))
				.buildAndInstall(tool);
		closeAllAction.addToWindowWhen(ProgramActionContext.class);

		tool.addAction(new SaveProgramAction(this, SAVE_GROUP, subMenuGroup));
		tool.addAction(new SaveAsProgramAction(this, SAVE_GROUP, subMenuGroup));

		DockingAction saveAllAction = new ActionBuilder("Save All Files", getName())
				.menuPath(ToolConstants.MENU_FILE, "Save All")
				.description("Save All Programs")
				.menuGroup(SAVE_GROUP, Integer.toString(subMenuGroup++))
				.enabledWhen(c -> programMgr.hasUnsavedPrograms())
				.onAction(c -> programSaveMgr.saveChangedPrograms())
				.buildAndInstall(tool);
		saveAllAction.addToWindowWhen(ProgramActionContext.class);

		tool.addAction(new ProgramOptionsAction(this));

		undoAction = new UndoAction(this, tool);
		redoAction = new RedoAction(this, tool);
		tool.addAction(undoAction);
		tool.addAction(redoAction);
	}

	void showProgramOptions(final Program currentProgram) {
		List<String> names = currentProgram.getOptionsNames();
		Options[] options = new Options[names.size()];
		for (int i = 0; i < names.size(); i++) {
			String optionName = names.get(i);
			options[i] = currentProgram.getOptions(optionName);
			if (optionName.equals("Program Information")) {
				setPropertyEditor(options[i], "Executable Location");
				options[i].setOptionsHelpLocation(new HelpLocation(getName(), "Program_Options"));
			}
		}
		OptionsDialog dialog = new OptionsDialog("Properties for " + currentProgram.getName(),
			"Properties", options, new OptionsEditorListener() {
				@Override
				public void beforeChangesApplied() {
					startTransaction(currentProgram);
				}

				@Override
				public void changesApplied() {
					endTransaction(currentProgram);
				}
			});
		dialog.setHelpLocation(new HelpLocation(HelpTopics.PROGRAM, "Program_Options"));
		tool.showDialog(dialog);
		dialog.dispose();
	}

	/**
	 * Set the string chooser property editor on the property that is a filename.
	 *
	 * @param options property list
	 * @param filePropertyName name of the property that is a filename
	 */
	private void setPropertyEditor(Options options, String filePropertyName) {
		PropertyEditor editor = options.getPropertyEditor(filePropertyName);
		if (editor == null && options.getType(filePropertyName) == OptionType.STRING_TYPE) {
			options.registerOption(filePropertyName, OptionType.STRING_TYPE, null, null, null,
				() -> new StringBasedFileEditor());
		}
	}

	/**
	 * Start a transaction if one has not been started; needed when program properties are about to
	 * change from the options editor.
	 */
	private void startTransaction(Program currentProgram) {
		if (transactionID < 0) {
			transactionID = currentProgram.startTransaction("Edit Program Properties");
		}
	}

	private void endTransaction(Program currentProgram) {
		if (transactionID >= 0) {
			currentProgram.endTransaction(transactionID, true);
			transactionID = -1;
		}
	}

	void contextChanged() {
		tool.contextChanged(null);
	}

	private void open() {

		OpenVersionedFileDialog<Program> openDialog =
			new OpenVersionedFileDialog<>(tool, "Open Program", Program.class);

		DomainFile startFile = null;
		Program p = getCurrentProgram();
		if (p != null) {
			startFile = p.getDomainFile();
		}
		openDialog.selectDomainFile(startFile);
		openDialog.setHelpLocation(new HelpLocation(HelpTopics.PROGRAM, "Open_File_Dialog"));

		openDialog.addOkActionListener(e -> {
			DomainFile domainFile = openDialog.getDomainFile();
			int version = openDialog.getVersion();
			if (domainFile == null) {
				openDialog.setStatusText("Please choose a Program");
			}
			else {
				openDialog.close();
				doOpenProgramSwing(new ProgramLocator(domainFile, version), OPEN_CURRENT);
			}
		});

		tool.showDialog(openDialog);
		contextChanged();
	}

	public void openPrograms(List<DomainFile> filesToOpen) {
		List<ProgramLocator> locators =
			filesToOpen.stream().map(f -> new ProgramLocator(f)).collect(Collectors.toList());

		openProgramLocations(locators);
	}

	private void openProgramLocations(List<ProgramLocator> locators) {
		if (locators.isEmpty()) {
			return;
		}
		Set<ProgramLocator> toOpen = new LinkedHashSet<>(locators); 	// preserve order

		// ensure already opened programs are visible in the tool
		Map<ProgramLocator, Program> alreadyOpen = getOpenPrograms(toOpen);
		makeVisibleInTool(alreadyOpen.values());
		toOpen.removeAll(alreadyOpen.keySet());

		// ensure cached programs are in the tool
		Map<ProgramLocator, Program> openedFromCache = openCachedProgramsInTool(toOpen);
		toOpen.removeAll(openedFromCache.keySet());

		// if nothing to open, make the first program in the list the current program
		if (toOpen.isEmpty()) {
			Program first = programMgr.getOpenProgram(locators.get(0));
			showProgram(first, locators.get(0), OPEN_CURRENT);
			return;
		}

		// Need to open at least one program. Make the first one to open the current program.
		OpenProgramTask task = new OpenProgramTask(new ArrayList<>(toOpen), this);
		new TaskLauncher(task, tool.getToolFrame());

		List<OpenProgramRequest> openProgramReqs = task.getOpenPrograms();

		int openState = OPEN_CURRENT;
		for (OpenProgramRequest programReq : openProgramReqs) {
			showProgram(programReq.getProgram(), programReq.getLocator(), openState);
			programReq.release();
			openState = OPEN_VISIBLE;
		}
	}

	private void makeVisibleInTool(Collection<Program> programs) {
		for (Program program : programs) {
			openProgram(program, OPEN_VISIBLE);
		}
	}

	private Map<ProgramLocator, Program> openCachedProgramsInTool(Set<ProgramLocator> toOpen) {
		Map<ProgramLocator, Program> map = new HashMap<>();
		for (ProgramLocator programLocator : toOpen) {
			Program program = programCache.get(programLocator);
			if (program != null) {
				openProgram(program, OPEN_VISIBLE);
				map.put(programLocator, program);
			}
		}
		return map;
	}

	private Map<ProgramLocator, Program> getOpenPrograms(Collection<ProgramLocator> locators) {
		Map<ProgramLocator, Program> map = new HashMap<>();
		for (ProgramLocator locator : locators) {
			Program program = programMgr.getOpenProgram(locator);
			if (program != null) {
				map.put(locator, program);
			}
		}
		return map;
	}

	@Override
	public void saveProgram() {
		saveProgram(getCurrentProgram());
	}

	@Override
	public void saveProgram(Program program) {
		Swing.runIfSwingOrRunLater(() -> programSaveMgr.saveProgram(program));
	}

	@Override
	public void saveProgramAs() {
		saveProgramAs(getCurrentProgram());
	}

	@Override
	public void saveProgramAs(Program program) {
		Swing.runIfSwingOrRunLater(() -> programSaveMgr.saveAs(program));
	}

	/**
	 * Write out my data state.
	 */
	@Override
	public void writeDataState(SaveState saveState) {

		ArrayList<ProgramInfo> programInfos = new ArrayList<>();
		for (Program p : programMgr.getAllPrograms()) {
			ProgramInfo info = programMgr.getInfo(p);
			if (info != null && info.canReopen()) {
				programInfos.add(info);
			}
		}

		saveState.putInt("NUM_PROGRAMS", programInfos.size());

		int i = 0;
		for (ProgramInfo programInfo : programInfos) {
			writeProgramInfo(programInfo, saveState, i++);
		}
		Program p = programMgr.getCurrentProgram();
		if (p != null) {
			ProjectLocator projectLocator = p.getDomainFile().getProjectLocator();
			if (projectLocator != null && !projectLocator.isTransient()) {
				saveState.putString("CURRENT_FILE", p.getDomainFile().getName());
				if (currentLocation != null) {
					currentLocation.saveState(saveState);
				}
			}
		}
	}

	/**
	 * Read in my data state.
	 */
	@Override
	public void readDataState(SaveState saveState) {
		if (!programMgr.isEmpty()) {
			currentLocation = null;
			return; // don't do anything restoring toolstate
		}
		loadPrograms(saveState);
		String currentFile = saveState.getString("CURRENT_FILE", null);

		List<Program> programs = programMgr.getAllPrograms();
		if (!programs.isEmpty()) {
			if (currentFile != null) {
				for (Program program : programs) {
					if (program.getDomainFile().getName().equals(currentFile)) {
						programMgr.setCurrentProgram(program);
						currentLocation = ProgramLocation.getLocation(program, saveState);
						break;
					}
				}
			}
			if (getCurrentProgram() == null) {
				programMgr.setCurrentProgram(programs.get(0));
			}
		}
		contextChanged();
	}

	@Override
	public void dataStateRestoreCompleted() {
		if (currentLocation != null) {
			tool.firePluginEvent(
				new ProgramLocationPluginEvent(getName(), currentLocation, getCurrentProgram()));
		}
	}

	private void writeProgramInfo(ProgramInfo programInfo, SaveState saveState, int index) {
		if (programInfo.getProgramLocator().isURL()) {
			URL url = programInfo.getProgramLocator().getURL();
			saveState.putString("URL_" + index, url.toString());
			return;
		}

		String projectLocation = null;
		String projectName = null;
		String path = null;

		Program program = programInfo.program;
		DomainFile df = program.getDomainFile();
		ProjectLocator projectLocator = df.getProjectLocator();
		if (projectLocator != null && !projectLocator.isTransient()) {
			projectLocation = projectLocator.getLocation();
			projectName = projectLocator.getName();
			path = df.getPathname();
		}
		int version = DomainFile.DEFAULT_VERSION;
		if (!df.isLatestVersion()) {
			version = df.getVersion();
		}

		saveState.putString("LOCATION_" + index, projectLocation);
		saveState.putString("PROJECT_NAME_" + index, projectName);
		saveState.putInt("VERSION_" + index, version);
		saveState.putString("PATHNAME_" + index, path);
	}

	/**
	 * Read in my data state.
	 */
	private void loadPrograms(SaveState saveState) {

		int programCount = saveState.getInt("NUM_PROGRAMS", 0);
		if (programCount == 0) {
			return;
		}
		List<ProgramLocator> openList = new ArrayList<>();

		for (int index = 0; index < programCount; index++) {

			URL url = getGhidraURL(saveState, index);
			if (url != null) {
				openList.add(new ProgramLocator(url));
				continue;
			}

			DomainFile domainFile = getDomainFile(saveState, index);
			if (domainFile != null) {
				int version = getVersion(saveState, index);
				openList.add(new ProgramLocator(domainFile, version));
			}
		}
		if (openList.isEmpty()) {
			return;
		}

		OpenProgramTask task = new OpenProgramTask(openList, this);

		// Restore state should not ask about checking out since
		// hopefully it is in the same state it was in when project
		// was closed and state was saved.
		task.setNoCheckout();

		new TaskLauncher(task, tool.getToolFrame(), 100);

		List<OpenProgramRequest> openProgramReqs = task.getOpenPrograms();
		for (OpenProgramRequest programReq : openProgramReqs) {
			ProgramLocator locator = programReq.getLocator();
			showProgram(programReq.getProgram(), locator, OPEN_VISIBLE);
			programReq.release();
		}
	}

	private URL getGhidraURL(SaveState saveState, int index) {
		String url = saveState.getString("URL_" + index, null);
		if (url == null) {
			return null;
		}
		try {
			return new URL(url);
		}
		catch (MalformedURLException e) {
			return null;
		}
	}

	private DomainFile getDomainFile(SaveState saveState, int index) {
		String pathname = saveState.getString("PATHNAME_" + index, null);
		String location = saveState.getString("LOCATION_" + index, null);
		String projectName = saveState.getString("PROJECT_NAME_" + index, null);
		if (location == null || projectName == null) {
			return null;
		}
		ProjectLocator projectLocator = new ProjectLocator(location, projectName);

		ProjectData projectData = tool.getProject().getProjectData(projectLocator);
		if (projectData == null) {
			return null;
		}

		DomainFile df = projectData.getFile(pathname);
		if (df == null) {
			String message = "Can't open program - \"" + pathname + "\"";
			int version = getVersion(saveState, index);
			if (version != DomainFile.DEFAULT_VERSION) {
				message += " version " + version;
			}
			Msg.showError(this, tool.getToolFrame(), "Program Not Found", message);
		}
		return df;
	}

	private int getVersion(SaveState saveState, int index) {
		return saveState.getInt("VERSION_" + index, DomainFile.DEFAULT_VERSION);
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof OpenProgramPluginEvent) {
			OpenProgramPluginEvent ev = (OpenProgramPluginEvent) event;
			openProgram(ev.getProgram());
		}
		else if (event instanceof CloseProgramPluginEvent) {
			CloseProgramPluginEvent ev = (CloseProgramPluginEvent) event;
			closeProgram(ev.getProgram(), ev.ignoreChanges());
		}
		else if (event instanceof ProgramActivatedPluginEvent) {
			Program p = ((ProgramActivatedPluginEvent) event).getActiveProgram();
			programMgr.setCurrentProgram(p);
		}
		else if (event instanceof ProgramLocationPluginEvent) {
			ProgramLocationPluginEvent ev = (ProgramLocationPluginEvent) event;
			currentLocation = ev.getLocation();
			firePluginEvent(new ExternalProgramLocationPluginEvent(getName(), currentLocation,
				ev.getProgram()));
		}
		else if (event instanceof ExternalProgramLocationPluginEvent) {
			Program currentProgram = programMgr.getCurrentProgram();
			if (currentProgram == null) {
				return;
			}
			ExternalProgramLocationPluginEvent ev = (ExternalProgramLocationPluginEvent) event;
			ProgramLocation loc = ev.getLocation();
			if (loc != null) {
				loc = localizeLocation(currentProgram, loc);
				if (loc != null &&
					currentProgram.getAddressFactory().isValidAddress(loc.getAddress()) &&
					currentProgram.getMemory().contains(loc.getAddress())) {

					firePluginEvent(
						new ProgramLocationPluginEvent(getName(), loc, ev.getProgram()));
				}
			}
		}
		else if (event instanceof ProgramSelectionPluginEvent) {
			ProgramSelectionPluginEvent ev = (ProgramSelectionPluginEvent) event;
			firePluginEvent(new ExternalProgramSelectionPluginEvent(getName(), ev.getSelection(),
				ev.getProgram()));
		}
		else if (event instanceof ExternalProgramSelectionPluginEvent) {
			Program currentProgram = programMgr.getCurrentProgram();
			ExternalProgramSelectionPluginEvent ev = (ExternalProgramSelectionPluginEvent) event;
			if (currentProgram == null) {
				return;
			}
			ProgramSelection sel = ev.getSelection();
			if (sel != null) {
				sel = localizeSelection(currentProgram, sel);
				if (hasValidAddresses(currentProgram, sel)) {
					firePluginEvent(
						new ProgramSelectionPluginEvent(getName(), sel, ev.getProgram()));
				}
			}
		}
	}

	private ProgramSelection localizeSelection(Program currentProgram, ProgramSelection sel) {
		if (hasValidAddresses(currentProgram, sel)) {
			return sel;
		}

		// if address set has no valid address sets, try to map it.
		AddressFactory addrFactory = currentProgram.getAddressFactory();
		AddressSpace defaultSpace = addrFactory.getDefaultAddressSpace();
		AddressSet locAddressSet = new AddressSet();
		AddressRangeIterator riter = sel.getAddressRanges();
		while (riter.hasNext()) {
			AddressRange range = riter.next();
			Address min = range.getMinAddress();
			Address max = range.getMaxAddress();
			try {
				min = defaultSpace.getAddress(min.getOffset());
				max = defaultSpace.getAddress(max.getOffset());
				locAddressSet.addRange(min, max);
			}
			catch (Exception e) {
				// not sure why this catch block is here...if you are smart enough to figure it
				// out, then fix the code and remove the block...or at least document the problem
			}
		}

		// THIS IS IMPRECISE because ProgramSelection might be a more specific
		// selection
		// like an interior program selection
		return new ProgramSelection(locAddressSet);
	}

	private ProgramLocation localizeLocation(Program currentProgram, ProgramLocation loc) {
		Address addr = loc.getAddress();
		Address refAddr = loc.getRefAddress();

		if (loc.isValid(currentProgram)) {
			return loc;
		}

		// if the location isn't in the current program, try to map it into the
		// default address space.
		AddressFactory addressFactory = currentProgram.getAddressFactory();
		try {
			addr = addressFactory.getAddress(addr.toString(true));
			if (addr == null) {
				return null;
			}
		}
		catch (Exception e) {
			return null;
		}
		if (refAddr != null) {
			try {
				refAddr = addressFactory.getAddress(refAddr.toString(true));
			}
			catch (Exception e) {
				refAddr = null;
			}
		}

		// THIS IS IMPRECISE because ProgramLocation might be a more specific
		// object like an operand field location.
		return new ProgramLocation(currentProgram, addr, loc.getComponentPath(), refAddr, 0, 0, 0);
	}

	private boolean hasValidAddresses(Program currentProgram, ProgramSelection sel) {
		AddressRangeIterator it = sel.getAddressRanges();
		AddressFactory af = currentProgram.getAddressFactory();
		while (it.hasNext()) {
			AddressRange range = it.next();
			if (!af.isValidAddress(range.getMinAddress())) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean isVisible(Program program) {
		return programMgr.isVisible(program);
	}

	@Override
	public void releaseProgram(Program program, Object owner) {
		if (programMgr.contains(program)) {
			programMgr.releaseProgram(program, owner);
			Msg.info(ClientUtil.class,
				"Released program from " + tool.getName() + " tool: " + program.getDomainFile());
		}
	}

	@Override
	public boolean setPersistentOwner(Program program, Object owner) {
		return programMgr.setPersistentOwner(program, owner);
	}

	public boolean isManaged(Program program) {
		return programMgr.contains(program);
	}
}
