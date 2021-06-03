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

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
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
import resources.ResourceManager;

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

	private boolean programChangedLocally;
	private boolean programChangedRemotely;
	private boolean programSaved;
	private boolean updateConflicts;

	public MyProgramChangesDisplayPlugin(PluginTool tool) {

		super(tool, false, false);

		folderListener = new ProgramFolderListener();
		transactionListener = new ProgramTransactionListener();
		tool.getProject().getProjectData().addDomainFolderChangeListener(folderListener);

		createActions();
	}

	private void createActions() {

		ImageIcon icon = ResourceManager.loadImage("images/vcMerge.png");
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

		icon = ResourceManager.loadImage("images/vcCheckIn.png");
		checkInAction = new DockingAction("CheckIn", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				AppInfo.getFrontEndTool()
						.checkIn(tool, currentProgram.getDomainFile());
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null && currentProgram.getDomainFile().canCheckin();
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
		programChangedLocally = false;
		programChangedRemotely = false;
		programSaved = false;
		program.removeTransactionListener(transactionListener);
		program.removeListener(this);
		disposeMarkerSets(program);
	}

	private void intializeChangeMarkers() {
		// set all the triggers for updating markers when initializing
		programChangedLocally = true;
		programChangedRemotely = true;
		programSaved = true;
		updateConflicts = true;
		updateChangeMarkers();
	}

	private void createMarkerSets(Program program) {
		currentMyChangeMarks =
			markerService.createAreaMarker("Changes: Unsaved", "My changes not yet saved", program,
				MY_CHANGE_PRIORITY, true, true, false, Color.darkGray);

		if (program.getDomainFile().isCheckedOut()) {
			trackServerChanges(program);
		}
	}

	private void trackServerChanges(Program program) {
		currentChangesSinceCheckoutMarks = markerService.createAreaMarker("Changes: Not Checked-In",
			"My saved changes made since I checked it out", program, CHANGES_SINCE_CO_PRIORITY,
			true, true, false, Color.GREEN);

		currentOtherChangeMarks = markerService.createAreaMarker("Changes: Latest Version",
			"Changes made by others to this program since I checked it out", program,
			OTHER_CHANGES_PRIORITY, true, true, false, Color.BLUE);

		currentConflictChangeMarks = markerService.createAreaMarker("Changes: Conflicting",
			"Changes made by others to this program that conflict with my changes", program,
			CONFLICT_PRIORITY, true, true, false, Color.RED);
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

		Swing.assertSwingThread(
			"Change markers must be manipulated on the Swing thread");

		if (currentProgram == null) {
			return;
		}

		ProgramChangeSet changeSet = currentProgram.getChanges();

		if (programChangedLocally) {
			currentMyChangeMarks.setAddressSetCollection(
				changeSet.getAddressSetCollectionSinceLastSave());
		}

		if (isTrackingServerChanges()) {
			if (programSaved) {
				currentChangesSinceCheckoutMarks.setAddressSetCollection(
					changeSet.getAddressSetCollectionSinceCheckout());
			}

			if (programChangedRemotely) {
				currentOtherChangeMarks.setAddressSetCollection(
					new SingleAddressSetCollection(otherChangeSet));
			}

			// only update conflict markers when server changeSet changes or we end a transaction
			if (programChangedRemotely || updateConflicts) {
				AddressSet intersect =
					changeSet.getAddressSetCollectionSinceCheckout()
							.getCombinedAddressSet()
							.intersect(
								otherChangeSet);
				currentConflictChangeMarks.setAddressSetCollection(
					new SingleAddressSetCollection(intersect));
			}
		}

		programChangedLocally = false;
		programChangedRemotely = false;
		programSaved = false;
		updateConflicts = false;
	}

	/**
	 * If version numbers are different, get changes made by others since my
	 * checkout and launch update thread if necessary.
	 */
	private void updateForDomainFileChanged() {
		DomainFile df = currentProgram.getDomainFile();

		int latestServerVersion = df.getLatestVersion();
		int latestLocalVersion = df.getVersion();
		// if the server version changes, schedule thread to get server changeSet
		// which will trigger an marker update for both the other and conflict marker sets.
		if (df.isCheckedOut() && serverVersion != latestServerVersion) {
			serverVersion = latestServerVersion;
			localVersion = latestLocalVersion;
			if (serverVersion == localVersion) {
				otherChangeSet = new AddressSet();
				programChangedRemotely = true;
				updateManager.update();
			}
			else {
				scheduleUpdatesFromServer(currentProgram);
			}
		}
		// else just the local version changed, update conflict sets.
		else if (latestLocalVersion != localVersion) {
			localVersion = latestLocalVersion;
			updateConflicts = true;
			updateManager.update();
		}
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
		programChangedLocally = true;
		if (ev.containsEvent(DomainObject.DO_OBJECT_SAVED)) {
			programSaved = true;
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
		public void transactionStarted(DomainObjectAdapterDB domainObj, Transaction tx) {
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

			monitor.checkCanceled(); // plugin was shut down while we were scheduled

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
			programChangedRemotely = true;
			updateManager.update();
		}
	}

	MarkerSet getExternalChangeMarkers() {
		return currentOtherChangeMarks;
	}
}
