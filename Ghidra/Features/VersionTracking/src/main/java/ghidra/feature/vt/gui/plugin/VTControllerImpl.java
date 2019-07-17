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
package ghidra.feature.vt.gui.plugin;

import java.awt.Component;
import java.io.IOException;
import java.util.*;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.feature.vt.api.db.VTAssociationDB;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.duallisting.VTListingContext;
import ghidra.feature.vt.gui.provider.markuptable.VTMarkupItemContext;
import ghidra.feature.vt.gui.task.SaveTask;
import ghidra.feature.vt.gui.task.VtTask;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.feature.vt.gui.util.MatchInfoFactory;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.main.SaveDataDialog;
import ghidra.framework.model.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.AddressCorrelation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakValueHashMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.*;

public class VTControllerImpl
		implements DomainObjectListener, OptionsChangeListener, TransactionListener, VTController {
	private VTSession session = null;
	private VTPlugin plugin;
	private List<VTControllerListener> listeners = new ArrayList<>();
	private AddressCorrelatorManager addressCorrelatorManager;
	private MatchInfoFactory matchInfoFactory;
	private Map<Address, Symbol> destinationSymbolCache = new WeakValueHashMap<>();
	private Map<Address, Symbol> sourceSymbolCache = new WeakValueHashMap<>();

	private ToolOptions vtOptions;
	private MatchInfo currentMatchInfo;
	private MyFolderListener folderListener;

	public VTControllerImpl(VTPlugin plugin) {
		this.plugin = plugin;
		addressCorrelatorManager = new AddressCorrelatorManager(this);
		matchInfoFactory = new MatchInfoFactory();
		vtOptions = plugin.getTool().getOptions(VERSION_TRACKING_OPTIONS_NAME);
		vtOptions.addOptionsChangeListener(this);
		folderListener = new MyFolderListener();
		plugin.getTool().getProject().getProjectData().addDomainFolderChangeListener(
			folderListener);
	}

	@Override
	public void addListener(VTControllerListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeListener(VTControllerListener listener) {
		listeners.remove(listener);
	}

	@Override
	public VTSession getSession() {
		return session;
	}

	@Override
	public void openVersionTrackingSession(DomainFile domainFile) {
		if (!checkForUnSavedChanges()) {
			return;
		}
		try {
			VTSessionDB newSession = (VTSessionDB) domainFile.getDomainObject(this, true, true,
				TaskMonitorAdapter.DUMMY_MONITOR);
			doOpenSession(newSession);
		}
		catch (VersionException e) {
			Msg.showError(this, null, "Can't open domainFile " + domainFile.getName(),
				e.getMessage());
		}
		catch (CancelledException e) {
			Msg.error(this, "Got unexexped cancelled exception", e);
		}
		catch (IOException e) {
			Msg.showError(this, null, "Can't open " + domainFile.getName(), e.getMessage());
		}
	}

	@Override
	public void openVersionTrackingSession(VTSession newSession) {
		if (!checkForUnSavedChanges()) {
			return;
		}
		if (newSession instanceof VTSessionDB) {
			((VTSessionDB) newSession).addConsumer(this);
		}
		doOpenSession(newSession);
	}

	private void doOpenSession(VTSession newSession) {
		new TaskLauncher(new OpenSessionTask(newSession), getParentComponent(), 0);
	}

	@Override
	public boolean closeVersionTrackingSession() {
		if (checkForUnSavedChanges()) {
			closeCurrentSessionIgnoringChanges();
			return true;
		}
		return false;
	}

	@Override
	public void closeCurrentSessionIgnoringChanges() {
		if (session == null) {
			return;
		}

		Program sourceProgram = getSourceProgram();
		sourceProgram.removeListener(this);

		Program destinationProgram = getDestinationProgram();
		destinationProgram.removeListener(this);
		session.removeListener(this);
		if (session instanceof VTSessionDB) {
			((VTSessionDB) session).removeTransactionListener(this);
		}
		plugin.getTool().setSubTitle("");
		disposeSession();
	}

	@Override
	public void dispose() {
		disposeSession();
		fireDisposed();
	}

	@Override
	public void readConfigState(SaveState saveState) {
		addressCorrelatorManager.readConfigState(saveState);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		addressCorrelatorManager.writeConfigState(saveState);
	}

	@Override
	public Program getSourceProgram() {
		if (session == null) {
			return null;
		}
		return session.getSourceProgram();
	}

	@Override
	public Program getDestinationProgram() {
		if (session == null) {
			return null;
		}
		return session.getDestinationProgram();
	}

	// returns true if the operation was not cancelled.
	@Override
	public boolean checkForUnSavedChanges() {
		if (session == null) {
			return true;
		}

		List<DomainFile> domainFiles = new ArrayList<>();
		domainFiles.addAll(plugin.getChangedProgramsInSourceTool());
		domainFiles.addAll(plugin.getChangedProgramsInDestinationTool());
		if (session instanceof VTSessionDB) {
			VTSessionDB sessionDB = (VTSessionDB) session;
			if (sessionDB.isChanged()) {
				domainFiles.add(sessionDB.getDomainFile());
			}
		}
		if (domainFiles.isEmpty()) {
			return true;
		}
		SaveDataDialog saveDataDialog = new SaveDataDialog(getTool());

		return saveDataDialog.showDialog(domainFiles);
	}

	private void disposeSession() {
		if (session == null) {
			return;
		}
		VTSession oldSession = session;
		session = null;
		currentMatchInfo = null;
		matchInfoFactory.clearCache();
		sourceSymbolCache.clear();
		destinationSymbolCache.clear();
		fireSessionChanged();
		((VTSessionDB) oldSession).release(this);
	}

	@Override
	public AddressCorrelation getCorrelator(Function source, Function destination) {
		return addressCorrelatorManager.getCorrelator(source, destination);
	}

	@Override
	public AddressCorrelation getCorrelator(Data source, Data destination) {
		return addressCorrelatorManager.getCorrelator(source, destination);
	}

	@Override
	public VTMarkupItem getCurrentMarkupForLocation(ProgramLocation location, Program program) {
		MatchInfo matchInfo = getMatchInfo();
		if (matchInfo == null) {
			return null;
		}
		return matchInfo.getCurrentMarkupForLocation(location, program);
	}

	@Override
	public List<VTMarkupItem> getMarkupItems(ActionContext context) {
		List<VTMarkupItem> markupItems = new ArrayList<>();
		if (context instanceof VTMarkupItemContext) {
			VTMarkupItemContext itemContext = (VTMarkupItemContext) context;
			markupItems = itemContext.getSelectedMarkupItems();
		}
		if (context instanceof VTListingContext) {
			VTListingContext listingContext = (VTListingContext) context;
			Program program = listingContext.getProgram();
			ProgramLocation location = listingContext.getLocation();
			if (location != null) {
				VTMarkupItem markupItem = getCurrentMarkupForLocation(location, program);
				if (markupItem != null) {
					markupItems.add(markupItem);
				}
			}
		}
		if (context instanceof CodeViewerActionContext) {
			CodeViewerActionContext listingContext = (CodeViewerActionContext) context;
			Program program = listingContext.getProgram();
			ProgramLocation location = listingContext.getLocation();
			if (location != null) {
				VTMarkupItem markupItem = getCurrentMarkupForLocation(location, program);
				if (markupItem != null) {
					markupItems.add(markupItem);
				}
			}
		}
		return markupItems;
	}

	@Override
	public ToolOptions getOptions() {
		return vtOptions;
	}

	@Override
	public Component getParentComponent() {
		return plugin.getTool().getToolFrame();
	}

	@Override
	public ServiceProvider getServiceProvider() {
		return plugin.getTool();
	}

	@Override
	public String getVersionTrackingSessionName() {
		if (session != null) {
			return session.getName();
		}
		return "";
	}

	@Override
	public void refresh() {
		plugin.getTool().contextChanged(null);
	}

	@Override
	public MatchInfo getMatchInfo() {
		return currentMatchInfo;
	}

	@Override
	public PluginTool getTool() {
		return plugin.getTool();
	}

	@Override
	public void setSelectedMatch(VTMatch match) {
		if (session == null) {
			return;
		}

		VTMatch currentMatch = currentMatchInfo == null ? null : currentMatchInfo.getMatch();
		if (match == currentMatch) {
			return;
		}

		currentMatchInfo = (match == null) ? null
				: matchInfoFactory.getMatchInfo(this, match, addressCorrelatorManager);

		fireMatchChanged(currentMatchInfo);
	}

	@Override
	public MatchInfo getMatchInfo(VTMatch match) {
		return (match == null) ? null
				: matchInfoFactory.getMatchInfo(this, match, addressCorrelatorManager);
	}

	private void fireSessionChanged() {
		List<VTControllerListener> copyOfListeners = new ArrayList<>(listeners);
		for (VTControllerListener listener : copyOfListeners) {
			listener.sessionChanged(session);
		}
		plugin.getTool().contextChanged(null);
	}

	private void fireSessionUpdated(DomainObjectChangedEvent ev) {
		for (VTControllerListener listener : listeners) {
			listener.sessionUpdated(ev);
		}
	}

	private void fireMatchChanged(MatchInfo matchInfo) {
		for (VTControllerListener listener : listeners) {
			listener.matchSelected(matchInfo);
		}
	}

	private void fireDisposed() {
		for (VTControllerListener listener : listeners) {
			listener.disposed();
		}
	}

	@Override
	public void setSelectedMarkupItem(VTMarkupItem markupItem) {
		if (session == null) {
			return;
		}
		fireMarkupItemSelected(markupItem);
	}

	@Override
	public void markupItemStatusChanged(VTMarkupItem item) {
		//
		// Unusual Code Note: VT uses many layers of caching.  Some items, when applied, will
		//                    affect other items for state like status.  We have to clear the
		//                    cache of markup items in the *association* and in the *match info*.
		//                    At issue, the association's cached items may will have a default
		//                    address value.  We may need to change this, so we have to reload
		//                    those items.   Also, the match info is the responsible party for
		//                    loading the default addresses, so we have to clear its cache too so
		//                    it will recompute the default addresses.  We document this here as
		//                    to not forget this lesson, as we have already done so once and this
		//                    multi-level caching is super complicated to understand and debug :\
		//
		VTAssociation association = item.getAssociation();
		if (association instanceof VTAssociationDB) {
			VTAssociationDB associationDB = (VTAssociationDB) association;
			associationDB.setInvalid();
		}
		matchInfoFactory.clearCacheForAssociation(association);
	}

	private void fireMarkupItemSelected(VTMarkupItem markupItem) {
		for (VTControllerListener listener : listeners) {
			listener.markupItemSelected(markupItem);
		}
	}

	@Override
	public AddressCorrelatorManager getCorrelator() {
		return addressCorrelatorManager;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		Object source = ev.getSource();

		if (source == session) {
			if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
				matchInfoFactory.clearMatchInfoInternalCache();
			}
		}
		else if (source == getDestinationProgram()) {
			destinationSymbolCache.clear();

			// save the session when the destination program has been saved to keep the
			// session and the destination program in sync, for things like undo.
			checkForSave(ev);
		}
		else { // must be source program
			matchInfoFactory.clearMatchInfoInternalCache();
			sourceSymbolCache.clear();
		}

		fireSessionUpdated(ev);
		refresh();
	}

	private void checkForSave(DomainObjectChangedEvent ev) {
		if (!ev.containsEvent(DomainObject.DO_OBJECT_SAVED)) {
			return;
		}

		if (session instanceof VTSessionDB) {
			VTSessionDB sessionDB = (VTSessionDB) session;
			DomainFile vtDomainFile = sessionDB.getDomainFile();
			SaveTask saveVersionTrackingTask = new SaveTask(vtDomainFile);
			TaskLauncher.launch(saveVersionTrackingTask);
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		for (VTControllerListener listener : listeners) {
			listener.optionsChanged(options);
		}
	}

	@Override
	public void gotoSourceLocation(ProgramLocation location) {
		plugin.gotoSourceLocation(location);
	}

	@Override
	public void gotoDestinationLocation(ProgramLocation location) {
		plugin.gotoDestinationLocation(location);
	}

	@Override
	public void runVTTask(VtTask task) {
		Program destinationProgram = getDestinationProgram();

		SystemUtilities.assertTrue(destinationProgram != null,
			"How did we run a task with no destination program?");

		// Not sure why this check is needed, but previously, it was in each of the VT tasks.
		// I suspect it is a crude way to keep the user from starting another task while another is
		// running.
		if (hasTransactionsOpen(destinationProgram, task)) {
			return;
		}

		int matchSetTransactionID = session.startTransaction(task.getTaskTitle());
		try {
			new TaskLauncher(task, getParentComponent());
		}
		finally {
			session.endTransaction(matchSetTransactionID, task.wasSuccessfull());
		}
		if (task.hasErrors()) {
			task.showErrors();
		}

	}

	private boolean hasTransactionsOpen(Program program, VtTask task) {
		Transaction transaction = program.getCurrentTransaction();
		if (transaction != null) {
			Msg.showWarn(this, null, "Unable to " + task.getTaskTitle(),
				"The program \"" + program.getName() + "\"already has a transaction open: " +
					transaction.getDescription());
			return true;
		}

		Transaction matchSetTransaction = session.getCurrentTransaction();
		if (matchSetTransaction != null) {
			Msg.showWarn(this, null, "Unable to " + task.getTaskTitle(),
				"Transaction already open for the Match Set Manager ");
			return true;
		}
		return false;
	}

	@Override
	public AddressSetView getSelectionInSourceTool() {
		return plugin.getSelectionInSourceTool();
	}

	@Override
	public AddressSetView getSelectionInDestinationTool() {
		return plugin.getSelectionInDestinationTool();
	}

	@Override
	public void setSelectionInSourceTool(AddressSetView sourceSet) {
		plugin.setSelectionInSourceTool(sourceSet);
	}

	@Override
	public void setSelectionInDestinationTool(AddressSetView destinationSet) {
		plugin.setSelectionInDestinationTool(destinationSet);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	@Override
	public void transactionEnded(DomainObjectAdapterDB domainObj) {
		// don't care
	}

	@Override
	public void transactionStarted(DomainObjectAdapterDB domainObj, Transaction tx) {
		// don't care
	}

	@Override
	public void undoStackChanged(DomainObjectAdapterDB domainObj) {
		plugin.updateUndoActions();

	}

	@Override
	public void undoRedoOccurred(DomainObjectAdapterDB domainObj) {
		// don't care
	}

	private class MyFolderListener extends DomainFolderListenerAdapter {

		@Override
		public void domainFileObjectReplaced(DomainFile file, DomainObject oldObject) {

			/**
			 * Special handling for when a file is checked-in.  The existing program has be moved
			 * to a proxy file (no longer in the project) so that it can be closed and the program
			 * re-opened with the new version after the check-in merge.
			 */
			if (session == null) {
				return;
			}
			if (session.getSourceProgram() != oldObject &&
				session.getDestinationProgram() != oldObject) {
				return;
			}
			Program newProgram;
			try {
				newProgram = (Program) file.getDomainObject(this, false, false,
					TaskMonitorAdapter.DUMMY_MONITOR);
			}
			catch (Exception e) {
				Msg.showError(this, getParentComponent(), "Error opening program " + file, e);
				return;
			}

			if (oldObject == session.getSourceProgram()) {
				session.updateSourceProgram(newProgram);
			}
			else if (oldObject == session.getDestinationProgram()) {
				session.updateDestinationProgram(newProgram);
			}
//			List<DomainObjectChangeRecord> events = new ArrayList<DomainObjectChangeRecord>();
//			events.add(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
//			domainObjectChanged(new DomainObjectChangedEvent(newProgram, events));
			matchInfoFactory.clearCache();
			fireSessionChanged();
		}
	}

	private class OpenSessionTask extends Task {

		private final VTSession newSession;

		public OpenSessionTask(VTSession newSession) {
			super("Opening VT Session: " + newSession.getName(), false, false, true, true);
			this.newSession = newSession;
		}

		@Override
		public void run(TaskMonitor monitor) {
			try {
				SwingUtilities.invokeAndWait(() -> {
					closeCurrentSessionIgnoringChanges();
					session = newSession;
					fireSessionChanged();

					Program sourceProgram = getSourceProgram();
					sourceProgram.addListener(VTControllerImpl.this);

					Program destinationProgram = getDestinationProgram();
					destinationProgram.addListener(VTControllerImpl.this);

					newSession.addListener(VTControllerImpl.this);
					if (newSession instanceof VTSessionDB) {
						((VTSessionDB) newSession).addTransactionListener(VTControllerImpl.this);
					}
					plugin.getTool().setSubTitle(newSession.getName());
				});
			}
			catch (Exception e) {
				Msg.showError(this, getParentComponent(), "Unexpected Exception",
					"Unexpected exception opening Version Tracking Session", e);
			}
		}
	}

	@Override
	public Symbol getDestinationSymbol(VTAssociation association) {
		if (session == null) {
			return null;
		}
		Address address = association.getDestinationAddress();
		Symbol symbol = destinationSymbolCache.get(address);
		if (symbol == null) {
			Program program = session.getDestinationProgram();
			symbol = program.getSymbolTable().getPrimarySymbol(address);
			destinationSymbolCache.put(address, symbol);
		}
		return symbol;
	}

	@Override
	public Symbol getSourceSymbol(VTAssociation association) {
		if (session == null) {
			return null;
		}
		Address address = association.getSourceAddress();
		Symbol symbol = sourceSymbolCache.get(address);
		if (symbol == null) {
			Program program = session.getSourceProgram();
			symbol = program.getSymbolTable().getPrimarySymbol(address);
			sourceSymbolCache.put(address, symbol);
		}
		return symbol;
	}

	@Override
	public ColorizingService getSourceColorizingService() {
		return plugin.getSourceColorizingService();
	}

	@Override
	public ColorizingService getDestinationColorizingService() {
		return plugin.getDestinationColorizingService();
	}
}
