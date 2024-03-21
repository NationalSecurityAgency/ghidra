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
import docking.widgets.OptionDialog;
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
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.SaveDataDialog;
import ghidra.framework.main.projectdata.actions.CheckoutsDialog;
import ghidra.framework.model.*;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.AddressCorrelation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.*;
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

	public VTControllerImpl(VTPlugin plugin) {
		this.plugin = plugin;
		addressCorrelatorManager = new AddressCorrelatorManager(this);
		matchInfoFactory = new MatchInfoFactory();
		vtOptions = plugin.getTool().getOptions(VERSION_TRACKING_OPTIONS_NAME);
		vtOptions.addOptionsChangeListener(this);
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

	private boolean checkSessionFileAccess(DomainFile domainFile) {

		DomainFolder folder = domainFile.getParent();
		if (folder == null || !folder.isInWritableProject()) {
			Msg.showError(this, null, "Can't open VT Session: " + domainFile,
				"VT Session file use limited to active project only.");
			return false;
		}
		if (domainFile.isVersioned()) {
			if (domainFile.isCheckedOut()) {
				if (!domainFile.isCheckedOutExclusive()) {
					Msg.showError(this, null, "Can't open VT Session: " + domainFile,
						"VT Session file is checked-out but does not have exclusive access.\n" +
							"You must undo checkout and re-checkout with exclusive access.");
					return false;
				}
				if (domainFile.isReadOnly()) {
					Msg.showError(this, null, "Can't open VT Session: " + domainFile,
						"VT Session file is set read-only which prevents its use.");
					return false;
				}
				return true;
			}
			return checkoutSession(domainFile);
		}
		else if (domainFile.isReadOnly()) { // non-versioned file
			Msg.showError(this, null, "Can't open VT Session: " + domainFile,
				"VT Session file is set read-only which prevents its use.");
			return false;
		}
		return true;
	}

	private boolean checkoutSession(DomainFile domainFile) {

		Project activeProject = AppInfo.getActiveProject();
		RepositoryAdapter repository = activeProject.getRepository();

		if (repository != null) {
			try {
				ItemCheckoutStatus[] checkouts = domainFile.getCheckouts();
				if (checkouts.length != 0) {
					int rc = OptionDialog.showOptionDialogWithCancelAsDefaultButton(null,
						"Checkout VT Session",
						"VT Session " + domainFile.getName() + " is NOT CHECKED OUT but " +
							"is checked-out by another user.\n" +
							"Opening VT Session requires an exclusive check out of this file.\n" +
							"Do you want to view the list of active checkouts for this file?",
						"View Checkout(s)...");
					if (rc != OptionDialog.OPTION_ONE) {
						return false;
					}

					CheckoutsDialog dialog = new CheckoutsDialog(plugin.getTool(),
						repository.getUser(), domainFile, checkouts);
					plugin.getTool().showDialog(dialog);

					return false;

				}
			}
			catch (IOException e) {
				Msg.showError(this, null, "Checkout VT Session Failed: " + domainFile.getName(),
					e.getMessage());
				return false;
			}
		}

		int rc = OptionDialog.showOptionDialogWithCancelAsDefaultButton(null, "Checkout VT Session",
			"VT Session " + domainFile.getName() + " is NOT CHECKED OUT.\n" +
				"Opening VT Session requires an exclusive check out of this file.\n" +
				"Do you want to Check Out this file?",
			"Checkout...");
		if (rc != OptionDialog.OPTION_ONE) {
			return false;
		}

		TaskLauncher.launchModal("Checkout VT Session", new MonitoredRunnable() {

			@Override
			public void monitoredRun(TaskMonitor monitor) {
				try {
					domainFile.checkout(true, monitor);
				}
				catch (CancelledException e) {
					// ignore
				}
				catch (IOException e) {
					Msg.showError(this, null, "Checkout VT Session Failed: " + domainFile.getName(),
						e.getMessage());
				}
			}
		});
		return domainFile.isCheckedOutExclusive();
	}

	@Override
	public boolean openVersionTrackingSession(DomainFile domainFile) {
		if (!VTSession.class.isAssignableFrom(domainFile.getDomainObjectClass())) {
			throw new IllegalArgumentException("File does not correspond to a VTSession");
		}
		if (!checkForUnSavedChanges()) {
			return false;
		}
		try {
			if (!checkSessionFileAccess(domainFile)) {
				return false;
			}

			VTSessionDB vtSessionDB = getVTSessionDB(domainFile, this);
			if (vtSessionDB != null) {
				try {
					openVersionTrackingSession(vtSessionDB);
					return true;
				}
				finally {
					vtSessionDB.release(this);
				}
			}
		}
		catch (CancelledException e) {
			// ignore - return false
		}
		catch (VersionException e) {
			VersionExceptionHandler.showVersionError(null, domainFile.getName(), "VT Session",
				"open", e);
		}
		catch (IOException e) {
			Msg.showError(this, null, "Can't open VT Session: " + domainFile.getName(),
				e.getMessage());
		}
		return false;
	}

	private static class OpenVTSessionTask extends Task {

		private final Object consumer;
		private final DomainFile vtSessionFile;

		Exception exception;
		VTSessionDB vtSessionDB;

		OpenVTSessionTask(DomainFile vtSessionFile, Object consumer) {
			super("Opening VT Session", true, false, true, true);
			this.vtSessionFile = vtSessionFile;
			this.consumer = consumer;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			try {
				vtSessionDB =
					(VTSessionDB) vtSessionFile.getDomainObject(consumer, true, true, monitor);
			}
			catch (Exception e) {
				exception = e;
			}
		}
	}

	private VTSessionDB getVTSessionDB(DomainFile vtSessionFile, Object consumer)
			throws IOException, VersionException, CancelledException {

		OpenVTSessionTask task = new OpenVTSessionTask(vtSessionFile, consumer);

		TaskLauncher.launch(task);

		if (task.exception != null) {
			if (task.exception instanceof CancelledException ce) {
				throw ce;
			}
			if (task.exception instanceof VersionException ve) {
				throw ve;
			}
			if (task.exception instanceof IOException ioe) {
				throw ioe;
			}
			throw new IOException("VTSessionDB failure", task.exception);
		}

		return task.vtSessionDB;
	}

	@Override
	public void openVersionTrackingSession(VTSession newSession) {
		// FIXME: new session wizard should have handled existing session before starting -
		// should be no need for this check
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

		currentMatchInfo =
			(match == null) ? null : matchInfoFactory.getMatchInfo(match, addressCorrelatorManager);

		fireMatchChanged(currentMatchInfo);
	}

	@Override
	public MatchInfo getMatchInfo(VTMatch match) {
		return (match == null) ? null
				: matchInfoFactory.getMatchInfo(match, addressCorrelatorManager);
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
			if (ev.contains(DomainObjectEvent.RESTORED)) {
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
		if (!ev.contains(DomainObjectEvent.SAVED)) {
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

		WrapperTask wrappedTask = new WrapperTask(task);

		int matchSetTransactionID = session.startTransaction(task.getTaskTitle());
		try {
			new TaskLauncher(wrappedTask, getParentComponent());
		}
		finally {
			session.endTransaction(matchSetTransactionID, task.wasSuccessfull());
		}
		if (task.hasErrors()) {
			task.showErrors();
		}
	}

	private boolean hasTransactionsOpen(Program program, VtTask task) {
		TransactionInfo transaction = program.getCurrentTransactionInfo();
		if (transaction != null) {
			Msg.showWarn(this, null, "Unable to " + task.getTaskTitle(),
				"The program \"" + program.getName() + "\"already has a transaction open: " +
					transaction.getDescription());
			return true;
		}

		TransactionInfo matchSetTransaction = session.getCurrentTransactionInfo();
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

	@Override
	public void transactionEnded(DomainObjectAdapterDB domainObj) {
		// don't care
	}

	@Override
	public void transactionStarted(DomainObjectAdapterDB domainObj, TransactionInfo tx) {
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

//==================================================================================================
// Inner Classes
//==================================================================================================

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

	/**
	 * A task wrapper that allows us to set the currently in-use task monitor for VT APIs to use
	 * when they are not explicitly passed a task monitor.
	 */
	private class WrapperTask extends Task {

		private final Task delegate;

		WrapperTask(Task t) {
			super(t.getTaskTitle(), t.canCancel(), t.hasProgress(), t.isModal(),
				t.getWaitForTaskCompleted());
			this.delegate = t;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {

			VTTaskMonitor.setTaskMonitor(monitor);
			try {
				delegate.run(monitor);
			}
			finally {
				VTTaskMonitor.setTaskMonitor(null);
			}
		}

	}
}
