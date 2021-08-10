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

import java.awt.Component;
import java.awt.event.ActionListener;
import java.beans.PropertyEditor;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.options.editor.*;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.task.OpenProgramTask;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.data.ProjectFileManager;
import ghidra.framework.main.OpenVersionedFileDialog;
import ghidra.framework.model.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.protocol.ghidra.*;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskLauncher;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
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
public class ProgramManagerPlugin extends Plugin implements ProgramManager {

	private static final String SAVE_GROUP = "DomainObjectSave";
	private static final String OPEN_GROUP = "DomainObjectOpen";
	private MultiProgramManager programMgr;
	private ProgramSaveManager programSaveMgr;
	private DockingAction openAction;
	private DockingAction saveAllAction;
	private DockingAction closeAction;
	private DockingAction saveAction;
	private DockingAction saveAsAction;
	private DockingAction optionsAction;
	private DockingAction closeOthersAction;
	private DockingAction closeAllAction;
	private int transactionID = -1;
	private OpenVersionedFileDialog openDialog;
	private boolean locked = false;
	private UndoAction undoAction;
	private RedoAction redoAction;
	private ProgramLocation currentLocation;

	public ProgramManagerPlugin(PluginTool tool) {
		super(tool);

		createActions();
		programMgr = new MultiProgramManager(this);
		programSaveMgr = new ProgramSaveManager(tool, this);
	}

	/**
	 * Method called if the plugin supports this domain file.
	 *
	 * @param data
	 *            the data to be used by the running tool
	 * @return false if data is not a Program object.
	 */
	@Override
	public boolean acceptData(DomainFile[] data) {
		if (data == null || data.length == 0) {
			return false;
		}

		if (locked) {
			Msg.showError(this, tool.getToolFrame(), "Open Program Failed",
				"Program manager is locked and cannot open additional programs");
			return false;
		}

		List<DomainFile> filesToOpen = new ArrayList<>();
		for (DomainFile domainFile : data) {
			if (domainFile == null) {
				continue;
			}
			if (!(Program.class.isAssignableFrom(domainFile.getDomainObjectClass()))) {
				continue;
			}
			filesToOpen.add(domainFile);
		}
		openPrograms(filesToOpen);

		return !filesToOpen.isEmpty();
	}

	@Override
	public Class<?>[] getSupportedDataTypes() {
		return new Class[] { Program.class };
	}

	@Override
	public Program openProgram(final URL ghidraURL, final int state) {
		if (locked) {
			Msg.showError(this, tool.getToolFrame(), "Open Program Failed",
				"Program manager is locked and cannot open additional programs");
			return null;
		}

		AtomicReference<Program> ref = new AtomicReference<>();
		Runnable r = () -> ref.set(doOpenProgram(ghidraURL, state));
		SystemUtilities.runSwingNow(r);
		return ref.get();
	}

	private void messageBadProgramURL(URL ghidraURL) {
		Msg.showError(this, null, "Invalid Ghidra URL",
			"Ghidra URL does not reference a Ghidra Program: " + ghidraURL);
	}

	protected Program doOpenProgram(URL ghidraURL, int openState) {
		if (!GhidraURL.isServerRepositoryURL(ghidraURL)) {
			Msg.showError(this, null, "Invalid Ghidra URL",
				"Ghidra URL does not reference a Ghidra Program: " + ghidraURL);
			return null;
		}
		Program openProgram = programMgr.getOpenProgram(ghidraURL);
		if (openProgram != null) {
			programMgr.addProgram(openProgram, GhidraURL.getNormalizedURL(ghidraURL), openState);
			updateActions();
			if (openState == ProgramManager.OPEN_CURRENT) {
				gotoProgramRef(openProgram, ghidraURL.getRef());
				programMgr.saveLocation();
			}
			return openProgram;
		}

		GhidraURLWrappedContent wrappedContent = null;
		Object content = null;
		try {
			GhidraURLConnection c = (GhidraURLConnection) ghidraURL.openConnection();
			Object obj = c.getContent();
			if (c.getResponseCode() == GhidraURLConnection.GHIDRA_UNAUTHORIZED) {
				return null; // assume user already notified
			}
			if (!(obj instanceof GhidraURLWrappedContent)) {
				messageBadProgramURL(ghidraURL);
				return null;
			}
			wrappedContent = (GhidraURLWrappedContent) obj;
			content = wrappedContent.getContent(this);
			if (!(content instanceof DomainFile)) {
				messageBadProgramURL(ghidraURL);
				return null;
			}
			DomainFile df = (DomainFile) content;
			if (!ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(df.getContentType())) {
				messageBadProgramURL(ghidraURL);
				return null;
			}

			OpenProgramTask task = new OpenProgramTask(df, true, this);
			TaskLauncher.launch(task);

			openProgram = task.getOpenProgram();
			if (openProgram == null) {
				return null;
			}

			programMgr.addProgram(openProgram, GhidraURL.getNormalizedURL(ghidraURL), openState);
			updateActions();
			openProgram.release(this);
			if (openState == ProgramManager.OPEN_CURRENT) {
				gotoProgramRef(openProgram, ghidraURL.getRef());
				programMgr.saveLocation();
			}
			return openProgram;
		}
		catch (NotFoundException e) {
			messageBadProgramURL(ghidraURL);
		}
		catch (MalformedURLException e) {
			Msg.showError(this, null, "Invalid Ghidra URL",
				"Improperly formed Ghidra URL: " + ghidraURL);
		}
		catch (IOException e) {
			Msg.showError(this, null, "Program Open Failed",
				"Failed to open Ghidra URL: " + e.getMessage());
		}
		finally {
			if (content != null) {
				wrappedContent.release(content, this);
			}
		}
		return null;
	}

	private boolean gotoProgramRef(Program program, String ref) {
		if (ref == null) {
			return false;
		}

		String trimmedRef = ref.trim();
		if (trimmedRef.length() == 0) {
			return false;
		}
		List<Symbol> symbols = NamespaceUtils.getSymbols(trimmedRef, program);
		Symbol sym = symbols.isEmpty() ? null : symbols.get(0);

		ProgramLocation loc = null;
		if (sym != null) {
			SymbolType type = sym.getSymbolType();
			if (type == SymbolType.FUNCTION) {
				loc = new FunctionSignatureFieldLocation(sym.getProgram(), sym.getAddress());
			}
			else if (type == SymbolType.LABEL) {
				loc = new LabelFieldLocation(sym);
			}
		}
		else {
			Address addr = program.getAddressFactory().getAddress(trimmedRef);
			if (addr != null && addr.isMemoryAddress()) {
				loc = new CodeUnitLocation(program, addr, 0, 0, 0);
			}
		}
		if (loc == null) {
			Msg.showError(this, null, "Navigation Failed",
				"Referenced label/function not found: " + trimmedRef);
			return false;
		}

		firePluginEvent(new ProgramLocationPluginEvent(getName(), loc, program));

		return true;
	}

	@Override
	public Program openProgram(DomainFile df) {
		return openProgram(df, -1, OPEN_CURRENT);
	}

	@Override
	public Program openProgram(DomainFile df, Component parent) {
		return openProgram(df, -1, OPEN_CURRENT);
	}

	@Override
	public Program openProgram(DomainFile df, int version) {
		return openProgram(df, version, OPEN_CURRENT);
	}

	@Override
	public Program openProgram(DomainFile domainFile, int version, int state) {

		if (domainFile == null) {
			throw new IllegalArgumentException("Domain file cannot be null");
		}
		if (locked) {
			Msg.showError(this, tool.getToolFrame(), "Open Program Failed",
				"Program manager is locked and cannot open additional programs");
			return null;
		}

		Program program = Swing.runNow(() -> {
			Program p = doOpenProgram(domainFile, version, state);
			updateActions();
			return p;
		});

		if (program != null) {
			Msg.info(this, "Opened program in " + tool.getName() + " tool: " + domainFile);
		}
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
		return programMgr.getAllPrograms();
	}

	@Override
	public void dispose() {
		programMgr.dispose();
		tool.clearLastEvents();
	}

	@Override
	public boolean closeOtherPrograms(final boolean ignoreChanges) {
		final Program[] otherPrograms = programMgr.getOtherPrograms();
		Runnable r = () -> doCloseAllPrograms(otherPrograms, ignoreChanges);
		SystemUtilities.runSwingNow(r);
		return programMgr.isEmpty();
	}

	@Override
	public boolean closeAllPrograms(final boolean ignoreChanges) {
		final Program[] openPrograms = programMgr.getAllPrograms();
		Runnable r = () -> doCloseAllPrograms(openPrograms, ignoreChanges);
		SystemUtilities.runSwingNow(r);
		return programMgr.isEmpty();
	}

	private void doCloseAllPrograms(Program[] openPrograms, boolean ignoreChanges) {
		List<Program> toRemove = new ArrayList<>();
		Program currentProgram = programMgr.getCurrentProgram();
		for (Program p : openPrograms) {
			if (ignoreChanges) {
				toRemove.add(p);
			}
			else if (p.isClosed()) {
				toRemove.add(p);
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
		updateActions();
	}

	@Override
	public boolean closeProgram(final Program program, final boolean ignoreChanges) {
		if (program == null) {
			return false;
		}
		Runnable r = () -> {
			// Note: The tool.canCloseDomainObject() call must come before the
			// programSaveMgr.canClose()call since plugins may save changes to the program
			// so that they can close.
			if (ignoreChanges || program.isClosed() || programMgr.isPersistent(program) ||
				(tool.canCloseDomainObject(program) && programSaveMgr.canClose(program))) {
				programMgr.removeProgram(program);
				updateActions();
			}
		};
		SystemUtilities.runSwingNow(r);
		return !programMgr.contains(program);
	}

	@Override
	protected void close() {
		Program[] programs = programMgr.getAllPrograms();
		if (programs.length == 0) {
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
		updateActions();
		tool.setSubTitle("");
		tool.clearLastEvents();
	}

	@Override
	public void setCurrentProgram(final Program p) {
		Runnable r = () -> {
			programMgr.setCurrentProgram(p);
			updateActions();
		};
		SystemUtilities.runSwingNow(r);
	}

	@Override
	public Program getProgram(Address addr) {
		return programMgr.getProgram(addr);

	}

	/**
	 * This method notifies listening plugins that a programs has been added to
	 * the program manager. This is not used for actually opening a program from
	 * the database and will act strangely if given a closed Program object.
	 *
	 * @see ghidra.app.services.ProgramManager#openProgram(ghidra.program.model.listing.Program)
	 */
	@Override
	public void openProgram(Program program) {
		openProgram(program, true);
	}

	@Override
	public void openProgram(Program program, boolean current) {
		openProgram(program, current ? OPEN_CURRENT : OPEN_VISIBLE);
	}

	@Override
	public void openProgram(final Program program, final int state) {
		if (locked) {
			throw new IllegalStateException(
				"Progam manager is locked and cannot accept a new program");
		}

		Runnable r = () -> {
			programMgr.addProgram(program, null, state);
			if (state == ProgramManager.OPEN_CURRENT) {
				programMgr.saveLocation();
			}
			updateActions();
		};
		SystemUtilities.runSwingNow(r);
	}

	@Override
	public boolean closeProgram() {
		return closeProgram(getCurrentProgram(), false);
	}

	@Override
	protected boolean saveData() {
		boolean result = programSaveMgr.canCloseAll();
		updateActions();
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

		int subMenuGroupOrder = 1;

		openAction = new ActionBuilder("Open File", getName())
				.menuPath(ToolConstants.MENU_FILE, "&Open...")
				.menuGroup(OPEN_GROUP, Integer.toString(subMenuGroupOrder++))
				.keyBinding("ctrl O")
				.onAction(c -> open())
				.buildAndInstall(tool);

		//		.withContext(ProgramActionContext.class)
		//		.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
		// openAction doesn't really use a context, but we want it to be in windows that
		// have providers that use programs. 
		openAction.addToWindowWhen(ProgramActionContext.class);

		closeAction = new ActionBuilder("Close File", getName())
				.menuPath(ToolConstants.MENU_FILE, "&Close")
				.menuGroup(OPEN_GROUP, Integer.toString(subMenuGroupOrder++))
				.withContext(ProgramActionContext.class)
				.supportsDefaultToolContext(true)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(c -> closeProgram(c.getProgram(), false))
				.keyBinding("ctrl W")
				.buildAndInstall(tool);

		closeOthersAction = new ActionBuilder("Close Others", getName())
				.menuPath(ToolConstants.MENU_FILE, "Close &Others")
				.menuGroup(OPEN_GROUP, Integer.toString(subMenuGroupOrder++))
				.enabled(false)
				.withContext(ProgramActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(c -> closeOtherPrograms(false))
				.buildAndInstall(tool);

		closeAllAction = new ActionBuilder("Close All", getName())
				.menuPath(ToolConstants.MENU_FILE, "Close &All")
				.menuGroup(OPEN_GROUP, Integer.toString(subMenuGroupOrder++))
				.withContext(ProgramActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(c -> closeAllPrograms(false))
				.enabled(false)
				.buildAndInstall(tool);

		saveAction = new ActionBuilder("Save File", getName())
				.menuPath(ToolConstants.MENU_FILE, "Save File")
				.description("Save Program")
				.menuGroup(SAVE_GROUP, Integer.toString(subMenuGroupOrder++))
				.menuIcon(null)
				.toolBarIcon("images/disk.png")
				.toolBarGroup(ToolConstants.TOOLBAR_GROUP_ONE)
				.keyBinding("ctrl S")
				.withContext(ProgramActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.supportsDefaultToolContext(true)
				.enabledWhen(c -> c.getProgram() != null && c.getProgram().isChanged())
				.onAction(c -> programSaveMgr.saveProgram(c.getProgram()))
				.buildAndInstall(tool);

		saveAsAction = new ActionBuilder("Save As File", getName())
				.menuPath(ToolConstants.MENU_FILE, "Save &As...")
				.menuGroup(SAVE_GROUP, Integer.toString(subMenuGroupOrder++))
				.withContext(ProgramActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.supportsDefaultToolContext(true)
				.onAction(c -> programSaveMgr.saveAs(c.getProgram()))
				.buildAndInstall(tool);

		saveAllAction = new ActionBuilder("Save All Files", getName())
				.menuPath(ToolConstants.MENU_FILE, "Save All")
				.description("Save All Programs")
				.menuGroup(SAVE_GROUP, Integer.toString(subMenuGroupOrder++))
				.withContext(ProgramActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(c -> programSaveMgr.saveChangedPrograms())
				.buildAndInstall(tool);

		optionsAction = new ActionBuilder("Program Options", getName())
				.menuPath(ToolConstants.MENU_EDIT, "P&rogram Options...")
				.description("Edit Options for current program")
				.menuGroup(ToolConstants.TOOL_OPTIONS_MENU_GROUP,
					ToolConstants.TOOL_OPTIONS_MENU_GROUP + "b")
				.withContext(ProgramActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.supportsDefaultToolContext(true)
				.onAction(c -> showProgramOptions(c.getProgram()))
				.buildAndInstall(tool);

		undoAction = new UndoAction(tool, getName());
		redoAction = new RedoAction(tool, getName());
		tool.addAction(undoAction);
		tool.addAction(redoAction);
	}

	private void showProgramOptions(final Program currentProgram) {
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
	}

	/**
	 * Set the string chooser property editor on the property that is a filename.
	 *
	 * @param options            property list
	 * @param filePropertyName name of the property that is a filename
	 */
	private void setPropertyEditor(Options options, String filePropertyName) {
		PropertyEditor editor = options.getPropertyEditor(filePropertyName);
		if (editor == null && options.getType(filePropertyName) == OptionType.STRING_TYPE) {
			options.registerOption(filePropertyName, OptionType.STRING_TYPE, null, null, null,
				new StringBasedFileEditor());
		}
	}

	/**
	 * Start a transaction if one has not been started; needed when program
	 * properties are about to change from the options editor.
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

	private void updateActions() {
		Program p = programMgr.getCurrentProgram();
		updateCloseAction(p);
		updateProgramOptionsAction(p);
		updateProgramActions();
		closeAllAction.setEnabled(p != null);
		optionsAction.setEnabled(p != null);
		Program[] programList = programMgr.getAllPrograms();
		closeOthersAction.setEnabled(programList.length > 1);
		tool.contextChanged(null);
	}

	private void updateSaveAction(Program p) {
		if (p == null) {
			saveAction.getMenuBarData().setMenuItemName("&Save");
			saveAction.setDescription("Save Program");
			saveAction.setEnabled(false);
		}
		else {
			String programName = "'" + p.getDomainFile().getName() + "'";
			saveAction.getMenuBarData().setMenuItemName("&Save " + programName);
			saveAction.setDescription("Save " + programName);
			saveAction.setEnabled(p.isChanged());
		}
	}

	private void updateSaveAsAction(Program p) {
		if (p == null) {
			saveAsAction.getMenuBarData().setMenuItemName("Save &As...");
		}
		else {
			String programName = "'" + p.getDomainFile().getName() + "'";
			saveAsAction.getMenuBarData().setMenuItemName("Save " + programName + " &As...");
		}
	}

	private void updateProgramOptionsAction(Program p) {
		if (p == null) {
			optionsAction.getMenuBarData().setMenuItemName("Program Options");
		}
		else {
			String programName = "'" + p.getDomainFile().getName() + "'";
			optionsAction.getMenuBarData().setMenuItemName("Options for " + programName + "...");
		}
		optionsAction.setEnabled(p != null);
	}

	private void updateCloseAction(Program p) {
		if (p == null) {
			closeAction.getMenuBarData().setMenuItemName("&Close");
			closeAction.setDescription("Close Program");
		}
		else {
			String programName = "'" + p.getDomainFile().getName() + "'";
			closeAction.getMenuBarData().setMenuItemName("&Close " + programName);
			closeAction.setDescription("<html>Close " + HTMLUtilities.escapeHTML(programName));
		}
		closeAction.setEnabled(p != null);
	}

	private void open() {
		if (openDialog == null) {
			ActionListener listener = e -> {
				DomainFile domainFile = openDialog.getDomainFile();
				int version = openDialog.getVersion();
				if (domainFile == null) {
					openDialog.setStatusText("Please choose a Program");
				}
				else {
					openDialog.close();
					doOpenProgram(domainFile, version, OPEN_CURRENT);
				}
			};
			DomainFileFilter filter = f -> {
				Class<?> c = f.getDomainObjectClass();
				return Program.class.isAssignableFrom(c);
			};
			openDialog = new OpenVersionedFileDialog(tool, "Open Program", filter);
			openDialog.setHelpLocation(new HelpLocation(HelpTopics.PROGRAM, "Open_File_Dialog"));
			openDialog.addOkActionListener(listener);
		}
		tool.showDialog(openDialog);
		updateActions();
	}

	public void openPrograms(List<DomainFile> filesToOpen) {
		OpenProgramTask openTask = null;
		for (DomainFile domainFile : filesToOpen) {
			if (programMgr.getOpenProgram(domainFile, -1) != null) {
				continue;
			}
			if (openTask == null) {
				openTask = new OpenProgramTask(domainFile, -1, this);
			}
			else {
				openTask.addProgramToOpen(domainFile, -1);
			}
		}
		if (openTask != null) {
			new TaskLauncher(openTask, tool.getToolFrame());
			List<Program> openPrograms = openTask.getOpenPrograms();

			for (Program program : openPrograms) {
				openProgram(program, OPEN_VISIBLE);
				program.release(this);
			}
			if (!openPrograms.isEmpty()) {
				openProgram(openPrograms.get(0), OPEN_CURRENT);
			}
		}
	}

	protected Program doOpenProgram(DomainFile domainFile, int version, int openState) {
		Program openProgram = programMgr.getOpenProgram(domainFile, version);
		if (openProgram != null) {
			openProgram(openProgram, openState);
			return openProgram;
		}
		OpenProgramTask task = new OpenProgramTask(domainFile, version, this);
		new TaskLauncher(task, tool.getToolFrame());
		openProgram = task.getOpenProgram();
		if (openProgram != null) {
			openProgram(openProgram, openState);
			openProgram.release(this);
		}
		return openProgram;
	}

	void updateProgramActions() {
		updateSaveAllAction();
		Program p = getCurrentProgram();
		updateSaveAction(getCurrentProgram());
		updateSaveAsAction(getCurrentProgram());
		undoAction.update(p);
		redoAction.update(p);
	}

	private void updateSaveAllAction() {
		boolean saveAllEnable = false;
		Program[] programList = programMgr.getAllPrograms();
		for (Program element : programList) {
			if (element.isChanged()) {
				saveAllEnable = true;
				break;
			}
		}
		saveAllAction.setEnabled(saveAllEnable);
	}

	/**
	 * Write out my data state.
	 */
	@Override
	public void writeDataState(SaveState saveState) {
		// Only remember programs from non-transient projects
		ArrayList<Program> programs = new ArrayList<>();
		for (Program p : programMgr.getAllPrograms()) {
			ProjectLocator projectLocator = p.getDomainFile().getProjectLocator();
			if (projectLocator != null && !projectLocator.isTransient()) {
				programs.add(p);
			}
		}
		saveState.putInt("NUM_PROGRAMS", programs.size());
		int i = 0;
		for (Program p : programs) {
			writeProgramInfo(p, saveState, i++);
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

		Program[] programs = programMgr.getAllPrograms();
		if (programs.length != 0) {
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
				programMgr.setCurrentProgram(programs[0]);
			}
		}
		updateActions();
	}

	@Override
	public void dataStateRestoreCompleted() {
		if (currentLocation != null) {
			tool.firePluginEvent(
				new ProgramLocationPluginEvent(getName(), currentLocation, getCurrentProgram()));
		}
	}

	private void writeProgramInfo(Program program, SaveState saveState, int index) {
		if (locked) {
			return; // do not save state when locked.
		}
		String projectLocation = null;
		String projectName = null;
		String path = null;
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
		int n = saveState.getInt("NUM_PROGRAMS", 0);
		if (n == 0) {
			return;
		}
		OpenProgramTask openTask = null;

		for (int index = 0; index < n; index++) {
			DomainFile domainFile = getDomainFile(saveState, index);
			if (domainFile == null) {
				continue;
			}
			int version = getVersion(saveState, index);

			if (openTask == null) {
				openTask = new OpenProgramTask(domainFile, version, this);
			}
			else {
				openTask.addProgramToOpen(domainFile, version);
			}
		}

		if (openTask == null) {
			return;
		}

		// Restore state should not ask about checking out since
		// hopefully it is in the same state it was in when project
		// was closed and state was saved.
		openTask.setNoCheckout();

		try {
			new TaskLauncher(openTask, tool.getToolFrame(), 100);
		}
		catch (RuntimeException e) {
			Msg.showError(this, tool.getToolFrame(), "Error Getting Domain File",
				"Can't open program", e);
		}

		List<Program> openPrograms = openTask.getOpenPrograms();
		for (Program program : openPrograms) {
			openProgram(program, OPEN_VISIBLE);
			program.release(this);
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
			// Viewed project not available
			try {
				projectData = new ProjectFileManager(projectLocator, false, false);
			}
			catch (NotOwnerException e) {
				Msg.showError(this, tool.getToolFrame(), "Program Open Failed",
					"Not project owner: " + projectLocator + "(" + pathname + ")");
				return null;
			}
			catch (IOException e) {
				Msg.showError(this, tool.getToolFrame(), "Program Open Failed",
					"Project error: " + e.getMessage());
				return null;
			}
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

	@Override
	public boolean isLocked() {
		return locked;
	}

	@Override
	public void lockDown(boolean state) {
		locked = state;
		openAction.setEnabled(!state);
	}

}
