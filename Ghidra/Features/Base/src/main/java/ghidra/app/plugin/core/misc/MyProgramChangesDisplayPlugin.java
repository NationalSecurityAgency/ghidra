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
/*
 * BreakPointServicePlugin.java
 *
 * Created on February 6, 2002, 11:13 AM
 */

package ghidra.app.plugin.core.misc;

import java.awt.Color;
import java.io.IOException;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import generic.theme.GColor;
import generic.theme.GIcon;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.MarkerService;
import ghidra.app.services.MarkerSet;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramChangeSet;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.SwingUpdateManager;
import ghidra.util.task.TaskMonitor;
import ghidra.util.worker.Job;
import ghidra.util.worker.Worker;

/**
 * Manages the markers to display areas where changes have occurred 
 */
@PluginInfo( //@formatter:off
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Indicates areas that have changed",
	description = "This plugin tracks program changes and indicates those areas by " +
			"creating changebars via the marker manager.  In addition to showing current " +
			"changes, it also tracks and displays changes by others if the program is shared.",
	servicesRequired = { MarkerService.class }
) //@formatter:on
public class MyProgramChangesDisplayPlugin extends ProgramPlugin implements DomainObjectListener {

	// priorities for the different change sets displayed - higher takes precedent when painting
	private final static int CHANGES_SINCE_CO_PRIORITY = MarkerService.CHANGE_PRIORITY;
	private final static int MY_CHANGE_PRIORITY = MarkerService.CHANGE_PRIORITY + 1;
	private final static int OTHER_CHANGES_PRIORITY = MarkerService.CHANGE_PRIORITY + 2;
	private final static int CONFLICT_PRIORITY = MarkerService.CHANGE_PRIORITY + 3;

	private static final Color BG_COLOR_MARKER_UNSAVED =
		new GColor("color.bg.plugin.myprogramchangesdisplay.markers.changes.unsaved");
	private static final Color BG_COLOR_MARKER_CONFLICTING =
		new GColor("color.bg.plugin.myprogramchangesdisplay.markers.changes.conflicting");
	private static final Color BG_COLOR_MARKER_LATEST =
		new GColor("color.bg.plugin.myprogramchangesdisplay.markers.changes.latest.version");
	private static final Color BG_COLOR_MARKER_NOT_CHECKED_IN =
		new GColor("color.bg.plugin.myprogramchangesdisplay.markers.changes.not.checked.in");

	private MarkerService markerService;

	private MarkerSet currentMyChangeMarks; // my changes since last save
	private MarkerSet currentChangesSinceCheckoutMarks; // mark changes since my checkout
	private MarkerSet currentOtherChangeMarks; // mark other changes since MY check out
	private MarkerSet currentConflictChangeMarks; // mark other changes that conflict with my changes

	private ProgramFolderListener folderListener;
	private TransactionListener transactionListener;
	private SwingUpdateManager updateManager;
	private Worker worker = Worker.createGuiWorker();

	private DockingAction checkInAction;
	private DockingAction mergeAction;

	private AddressSetView otherChangeSet;
	private int serverVersion = -1;
	private int localVersion = -1;

	// currentProgram object changed; affects currentMyChangeMarks
	private boolean currentProgramChanged;

	// domain file updated on server; affects currentOtherChangeMarks
	private boolean domainFileChangedRemotely;

	// domain file updated locally; affects currentChangesSinceCheckoutMarks
	private boolean domainFileChangedLocally;

	// flag to force update of currentConflictChangeMarks
	private boolean updateConflicts;

	public MyProgramChangesDisplayPlugin(PluginTool tool) {

		super(tool);

		folderListener = new ProgramFolderListener();
		transactionListener = new ProgramTransactionListener();
		tool.getProject().getProjectData().addDomainFolderChangeListener(folderListener);

		createActions();
	}

	private void createActions() {

		Icon icon = new GIcon("icon.plugin.myprogramchanges.merge");
		mergeAction = new DockingAction("Update", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				AppInfo.getFrontEndTool().merge(tool, currentProgram.getDomainFile(), null);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null && currentProgram.getDomainFile().canMerge();
			}
		};

		mergeAction.setToolBarData(new ToolBarData(icon, "Repository"));
		mergeAction.setDescription("Update checked out file with latest version");
		mergeAction.setHelpLocation(new HelpLocation("VersionControl", mergeAction.getName()));

		icon = new GIcon("icon.plugin.myprogramchanges.checkin");
		checkInAction = new DockingAction("CheckIn", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				AppInfo.getFrontEndTool().checkIn(tool, currentProgram.getDomainFile());
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null &&
					currentProgram.getDomainFile().modifiedSinceCheckout();
			}
		};

		checkInAction.setToolBarData(new ToolBarData(icon, "Repository"));
		checkInAction.setDescription("Check in file");
		checkInAction.setHelpLocation(new HelpLocation("VersionControl", checkInAction.getName()));

		tool.addAction(mergeAction);
		tool.addAction(checkInAction);
	}

	@Override
	public void init() {
		markerService = tool.getService(MarkerService.class);
		updateManager = new SwingUpdateManager(1000, () -> updateChangeMarkers());
	}

	@Override
	protected void programActivated(Program program) {

		program.addListener(this);
		program.addTransactionListener(transactionListener);
		updateForDomainFileChanged();

		createMarkerSets(program);
		intializeChangeMarkers();
	}

	@Override
	protected void programDeactivated(Program program) {

		serverVersion = -1;
		localVersion = -1;
		currentProgramChanged = false;
		domainFileChangedRemotely = false;
		domainFileChangedLocally = false;
		program.removeTransactionListener(transactionListener);
		program.removeListener(this);
		disposeMarkerSets(program);
	}

	private void intializeChangeMarkers() {
		// set all the triggers for updating markers when initializing
		currentProgramChanged = true;
		domainFileChangedRemotely = true;
		domainFileChangedLocally = true;
		updateConflicts = true;
		updateChangeMarkers();
	}

	private void createMarkerSets(Program program) {
		currentMyChangeMarks =
			markerService.createAreaMarker("Changes: Unsaved", "My changes not yet saved", program,
				MY_CHANGE_PRIORITY, true, true, false, BG_COLOR_MARKER_UNSAVED);

		if (program.getDomainFile().isCheckedOut()) {
			trackServerChanges(program);
		}
	}

	private void trackServerChanges(Program program) {
		currentChangesSinceCheckoutMarks = markerService.createAreaMarker("Changes: Not Checked-In",
			"My saved changes made since I checked it out", program, CHANGES_SINCE_CO_PRIORITY,
			true, true, false, BG_COLOR_MARKER_NOT_CHECKED_IN);

		currentOtherChangeMarks = markerService.createAreaMarker("Changes: Latest Version",
			"Changes made by others to this program since I checked it out", program,
			OTHER_CHANGES_PRIORITY, true, true, false, BG_COLOR_MARKER_LATEST);

		currentConflictChangeMarks = markerService.createAreaMarker("Changes: Conflicting",
			"Changes made by others to this program that conflict with my changes", program,
			CONFLICT_PRIORITY, true, true, false, BG_COLOR_MARKER_CONFLICTING);
	}

	private void disposeMarkerSets(Program program) {

		markerService.removeMarker(currentMyChangeMarks, program);
		markerService.removeMarker(currentChangesSinceCheckoutMarks, program);
		markerService.removeMarker(currentOtherChangeMarks, program);
		markerService.removeMarker(currentConflictChangeMarks, program);

		currentMyChangeMarks = null;
		currentChangesSinceCheckoutMarks = null;
		currentOtherChangeMarks = null;
		currentConflictChangeMarks = null;
	}

	@Override
	public void dispose() {

		worker.dispose();
		if (currentProgram != null) {
			currentProgram.removeTransactionListener(transactionListener);
			currentProgram.removeListener(this);
		}

		tool.getProject().getProjectData().removeDomainFolderChangeListener(folderListener);

		if (updateManager != null) {
			updateManager.dispose();
			updateManager = null;
		}

		if (currentProgram != null) {
			disposeMarkerSets(currentProgram);
		}

		markerService = null;

		super.dispose();
	}

	/**
	 * Update markers that show my changes.
	 */
	private void updateChangeMarkers() {

		Swing.assertSwingThread("Change markers must be manipulated on the Swing thread");

		if (currentProgram == null) {
			return;
		}

		ProgramChangeSet changeSet = currentProgram.getChanges();

		if (currentProgramChanged) {
			currentMyChangeMarks
					.setAddressSetCollection(changeSet.getAddressSetCollectionSinceLastSave());
		}

		if (isTrackingServerChanges()) {
			if (domainFileChangedLocally) {
				currentChangesSinceCheckoutMarks
						.setAddressSetCollection(changeSet.getAddressSetCollectionSinceCheckout());
			}

			if (domainFileChangedRemotely) {
				currentOtherChangeMarks
						.setAddressSetCollection(new SingleAddressSetCollection(otherChangeSet));
			}

			// Update conflict markers when forced by server version change,
			// local version change (merge may have occured) or a transaction has ended
			if (updateConflicts) {
				AddressSet intersect = changeSet.getAddressSetCollectionSinceCheckout()
						.getCombinedAddressSet()
						.intersect(otherChangeSet);
				currentConflictChangeMarks
						.setAddressSetCollection(new SingleAddressSetCollection(intersect));
			}
		}

		currentProgramChanged = false;
		domainFileChangedRemotely = false;
		domainFileChangedLocally = false;
		updateConflicts = false;
	}

	/**
	 * If version numbers are different, get changes made by others since my
	 * checkout and launch update thread if necessary.
	 */
	private void updateForDomainFileChanged() {

		DomainFile df = currentProgram.getDomainFile();
		if (!df.isCheckedOut()) {
			// Only currentMyChangeMarks are maintained using domain object change listener
			// when file is not checked-out
			return;
		}

		int latestServerVersion = df.getLatestVersion();
		int latestLocalVersion = df.getVersion();

		boolean localVersionChanged = localVersion != latestLocalVersion;
		boolean serverVersionChanged = serverVersion != latestServerVersion;
		if (!localVersionChanged && !serverVersionChanged) {
			return; // No update to change bars
		}

		localVersion = latestLocalVersion;
		serverVersion = latestServerVersion;

		domainFileChangedLocally |= localVersionChanged;
		domainFileChangedRemotely |= serverVersionChanged;
		updateConflicts = true;

		if (localVersion == serverVersion) {
			// When server and local versions match otherChangeSet is empty
			otherChangeSet = new AddressSet();
			domainFileChangedRemotely = true;
		}
		else if (serverVersionChanged) {
			// Use UpdateChangeSetJob to compute the otherChangeSet
			// GUI update deferred to UpdateChangeSetJob
			scheduleUpdatesFromServer(currentProgram);
			return;
		}

		updateManager.update();
	}

	private void scheduleUpdatesFromServer(Program p) {
		// ensure we never have more than one pending job
		worker.clearPendingJobs();

		DomainFile file = p.getDomainFile();
		worker.schedule(new UpdateChangeSetJob(file));
	}

	public boolean isTrackingServerChanges() {
		return currentChangesSinceCheckoutMarks != null;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		currentProgramChanged = true;
		if (ev.contains(DomainObjectEvent.SAVED)) {
			domainFileChangedLocally = true;
		}

		updateManager.update();
	}

	Worker getWorker() {
		return worker;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class ProgramTransactionListener implements TransactionListener {

		@Override
		public void transactionStarted(DomainObjectAdapterDB domainObj, TransactionInfo tx) {
			// ignore
		}

		@Override
		public void transactionEnded(DomainObjectAdapterDB domainObj) {
			updateConflicts = true;
			updateManager.update();
		}

		@Override
		public void undoStackChanged(DomainObjectAdapterDB domainObj) {
			// ignore
		}

		@Override
		public void undoRedoOccurred(DomainObjectAdapterDB domainObj) {
			updateConflicts = true;
			updateManager.update();
		}
	}

	private class ProgramFolderListener extends DomainFolderListenerAdapter {

		@Override
		public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {

			Swing.runLater(() -> {
				if (currentProgram == null) {
					return;
				}

				DomainFile domainFile = currentProgram.getDomainFile();
				if (!file.equals(domainFile)) {
					return;
				}

				if (domainFile.isCheckedOut()) {
					if (!isTrackingServerChanges()) {
						trackServerChanges(currentProgram);
					}
					updateForDomainFileChanged();
				}
			});
		}
	}

	/** A job to grab program changes from the server */
	private class UpdateChangeSetJob extends Job {

		private DomainFile domainFile;

		UpdateChangeSetJob(DomainFile domainFile) {
			this.domainFile = domainFile;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {

			if (localVersion == serverVersion) {
				return; // skip update if versions now match
			}

			monitor.checkCancelled(); // plugin was shut down while we were scheduled

			ProgramChangeSet changes = null;
			try {
				changes = (ProgramChangeSet) domainFile.getChangesByOthersSinceCheckout();
			}
			catch (IOException e) {
				Msg.warn(this, "Unable to determine program change set: " + e.getMessage());
				return;
			}
			catch (Exception e) {
				ClientUtil.handleException(tool.getProject().getRepository(), e, "Get Change Set",
					false, tool.getToolFrame());
				return;
			}

			AddressSetView remoteChanges =
				changes != null ? changes.getAddressSet() : new AddressSet();
			Swing.runNow(() -> applyChanges(remoteChanges));
		}

		private void applyChanges(AddressSetView remoteChanges) {

			if (isDisposed()) {
				return; // plugin was shut down while we were running
			}

			otherChangeSet = remoteChanges;
			domainFileChangedRemotely = true;
			updateConflicts = true;
			updateManager.update();
		}
	}

	MarkerSet getExternalChangeMarkers() {
		return currentOtherChangeMarks;
	}
}
