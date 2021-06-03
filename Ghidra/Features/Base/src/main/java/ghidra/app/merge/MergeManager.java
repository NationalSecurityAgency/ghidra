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
package ghidra.app.merge;

import java.awt.*;
import java.lang.reflect.InvocationTargetException;
import java.util.Hashtable;

import javax.swing.JComponent;
import javax.swing.SwingUtilities;

import docking.help.Help;
import docking.help.HelpService;
import generic.util.WindowUtilities;
import ghidra.framework.data.DomainObjectMergeManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.framework.plugintool.ModalPluginTool;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.model.listing.DomainObjectChangeSet;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/** 
 * Top level object that manages each step of the merge/resolve conflicts
 * process.
 */
public abstract class MergeManager implements DomainObjectMergeManager {

	protected MergeResolver[] mergeResolvers;

	protected UndoableDomainObject resultDomainObject; // where changes will be merged to
	protected UndoableDomainObject myDomainObject; // source of changes to be applied
	protected UndoableDomainObject originalDomainObject; // original version that was checked out
	protected UndoableDomainObject latestDomainObject; // latest version of the program
	protected DomainObjectChangeSet latestChangeSet;
	protected DomainObjectChangeSet myChangeSet;

	protected MergeManagerPlugin mergePlugin;
//	protected ListingMergePanelPlugin listingPlugin;
//	protected GoToAddressLabelPlugin goToPlugin;
	protected RunManager runManager;
	protected TaskMonitor mergeMonitor; // The smaller "Check In" monitor which is the parent of the actual merge tool.
	private volatile boolean isCancelled;
	protected int currentIndex;
	protected volatile boolean inputReceived;
	protected boolean mergeStatus;
	protected volatile boolean prompting;
	protected volatile boolean mergeCompleted;
	protected volatile boolean mergeToolIsVisible;
	protected volatile ModalPluginTool mergeTool;
	protected Hashtable<String, Object> resolveMap;
//	protected ListingMergePanel mergePanel;
	protected MergeProgressPanel mergeProgressPanel;

//	protected boolean isShowingListingMergePanel = false;

	public MergeManager(UndoableDomainObject resultDomainObject,
			UndoableDomainObject myDomainObject, UndoableDomainObject originalDomainObject,
			UndoableDomainObject latestDomainObject, DomainObjectChangeSet latestChangeSet,
			DomainObjectChangeSet myChangeSet) {
		this.resultDomainObject = resultDomainObject;
		this.myDomainObject = myDomainObject;
		this.originalDomainObject = originalDomainObject;
		this.latestDomainObject = latestDomainObject;
		this.latestChangeSet = latestChangeSet;
		this.myChangeSet = myChangeSet;

		runManager = new RunManager();
		runManager.showCancelButton(false);

		resolveMap = new Hashtable<>();

		createMergeResolvers();
	}

	protected abstract void createMergeResolvers();

	/**
	 * Returns one of the four programs involved in the merge as indicated by the version.
	 * @param version the program version to return. (LATEST, MY, ORIGINAL, or RESULT).
	 * @return the indicated program version or null if a valid version isn't specified.
	 * @see MergeConstants
	 */
	public UndoableDomainObject getDomainObject(int version) {
		switch (version) {
			case MergeConstants.LATEST:
				return latestDomainObject;
			case MergeConstants.MY:
				return myDomainObject;
			case MergeConstants.ORIGINAL:
				return originalDomainObject;
			case MergeConstants.RESULT:
				return resultDomainObject;
			default:
				return null;
		}
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.framework.data.DomainObjectMergeManager#merge()
	 * 
	 * Begin the merge process by displaying a modal tool.
	 * The dialog's component is updated for each part of the 
	 * merge process that requires user input.
	 * 
	 *
	 */
	@Override
	public boolean merge(TaskMonitor taskMonitor) throws CancelledException {
		isCancelled = false;
		mergeMonitor = taskMonitor;
		mergeMonitor.initialize(mergeResolvers.length);
		if (mergeMonitor instanceof TaskDialog) {
			((TaskDialog) taskMonitor).setCancelEnabled(false);
		}
		mergeStatus = true;
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					runManager.showProgressIcon(false);

					// For now just get the phases in order and assume the displayed phase info
					// is nested correctly.
					mergeProgressPanel = new MergeProgressPanel();
					for (MergeResolver mergeResolver : mergeResolvers) {
						String[][] phaseArray = mergeResolver.getPhases();
						for (String[] element : phaseArray) {
							mergeProgressPanel.addInfo(element);
						}
					}
					mergeTool = ModalPluginTool.createTool(getMergeTitle());
					mergePlugin =
						createMergeManagerPlugin(mergeTool, MergeManager.this, resultDomainObject);

					Dimension d = getPreferredMergeToolSize();
					mergeTool.setSize(d.width, d.height);
					Point centerLoc = WindowUtilities.centerOnScreen(mergeTool.getSize());
					mergeTool.setLocation(centerLoc.x, centerLoc.y);

					initializeMerge();

					try {
						mergeTool.addPlugin(mergePlugin);
						// Adjust the size of the monitor component at the bottom of the merge tool.
						final JComponent monitorComp = runManager.getMonitorComponent();
						Dimension monitorDim = monitorComp.getPreferredSize();
						monitorDim.width = 500;
						monitorComp.setPreferredSize(monitorDim);
						mergeTool.addStatusComponent(monitorComp, true, false);
					}
					catch (PluginException e) {
						Msg.error(this, e);
					}

					SwingUtilities.invokeLater(() -> scheduleMerge());

					// Show the tool while the merge is occurring and block until merge completes.
					mergeTool.setVisible(true);

					conflictsResolveCompleted(); // make sure we cleanup tool

					cleanupMerge();
				}

				private String getMergeTitle() {
					DomainFile domainFile = resultDomainObject.getDomainFile();
					return "Merge Tool: " + domainFile.toString();
				}
			});
		}
		catch (InterruptedException e) {
		}
		catch (InvocationTargetException e) {
			e.printStackTrace();
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new CancelledException();
		}
		finally {
			mergeCompleted = true;
			if (mergeMonitor instanceof TaskDialog) {
				((TaskDialog) taskMonitor).setCancelEnabled(true);
			}
		}

		MergeManagerProvider provider = mergePlugin.getProvider();
		if (taskMonitor.isCancelled() || provider.mergeWasCanceled()) {
			throw new CancelledException();
		}
		return mergeStatus;
	}

	protected abstract MergeManagerPlugin createMergeManagerPlugin(ModalPluginTool mergePluginTool,
			MergeManager multiUserMergeManager, UndoableDomainObject modifiableDomainObject);

	protected abstract void initializeMerge();

	protected abstract void cleanupMerge();

	protected Dimension getPreferredMergeToolSize() {
		Dimension screenDim = Toolkit.getDefaultToolkit().getScreenSize();
		return new Dimension(screenDim.width - 200, screenDim.height - 200);
	}

	/**
	 * Convenience method for Junit tests.
	 */
	public boolean merge() throws CancelledException {
		return merge(TaskMonitorAdapter.DUMMY_MONITOR);
	}

	/**
	 * Enable the apply button according to the "enabled" parameter.
	 */
	@Override
	public void setApplyEnabled(final boolean enabled) {
		Runnable r = () -> mergePlugin.setApplyEnabled(enabled);

		if (SwingUtilities.isEventDispatchThread()) {
			r.run();
		}
		else {
			try {
				SwingUtilities.invokeAndWait(r);
			}
			catch (InterruptedException e) {
			}
			catch (InvocationTargetException e) {
				Msg.showError(this, null, "Error in Merge Dialog",
					"Error setting enablement for Apply button", e);
			}
		}
	}

	/**
	 * Clear the status text on the merge dialog.
	 *
	 */
	@Override
	public void clearStatusText() {
		mergeTool.clearStatusInfo();
	}

	/**
	 * Set the status text on the merge dialog.
	 */
	@Override
	public void setStatusText(String msg) {
		mergeTool.setStatusInfo(msg);
	}

	/**
	 * Show the default merge panel. The default merge panel now shows the status of each phase
	 * of the merge and also the progress in the current phase.
	 *@param description description of current merge process near the top of the merge tool.
	 */
	public void showDefaultMergePanel(final String description) {
		showComponent(null, null, null);
		SwingUtilities.invokeLater(() -> mergePlugin.updateMergeDescription(description));
	}

	/**
	 * Show the component that is used to resolve conflicts. This method
	 * is called by the MergeResolvers when user input is required. If the
	 * component is not null, this method blocks until the user either 
	 * cancels the merge process or resolves a conflict. If comp is null,
	 * then the default component is displayed, and the method does not
	 * wait for user input.
	 * @param comp component to show; if component is null, show the 
	 * default component and do not block
	 * @param componentID id or name for the component
	 */
	@Override
	public void showComponent(final JComponent comp, final String componentID,
			HelpLocation helpLoc) {

		HelpService help = Help.getHelpService();
		if (helpLoc != null && comp != null) {
			help.registerHelp(comp, helpLoc);
		}
		SwingUtilities.invokeLater(() -> {
			showMergeTool();
			Dimension oldSize = mergeTool.getSize();
			if (comp == null) {
				mergePlugin.showDefaultComponent();
			}
			else {
				mergePlugin.setMergeComponent(comp, componentID);
			}
			Dimension newSize = mergeTool.getSize();
			if (!newSize.equals(oldSize)) {
				Point centerLoc = WindowUtilities.centerOnScreen(mergeTool.getSize());
				mergeTool.setLocation(centerLoc.x, centerLoc.y);
			}
		});
		if (comp != null) {
			inputReceived = false;
			// block until the user takes action
			waitForInput();
		}
	}

	/**
	 * Removes the component that is used to resolve conflicts. This method
	 * is called by the MergeResolvers when user input is no longer required
	 * using the specified component. 
	 * @param comp component to show; if component is null, show the 
	 * default component and do not block
	 */
	public void removeComponent(final JComponent comp) {

		SwingUtilities.invokeLater(() -> mergePlugin.removeMergeComponent(comp));
	}

	protected void showMergeTool() {
		if (!mergeToolIsVisible) {
			mergeToolIsVisible = true;
			// center tool on screen
			Point centerLoc = WindowUtilities.centerOnScreen(mergeTool.getSize());
			mergeTool.setLocation(centerLoc.x, centerLoc.y);
		}
	}

	/**
	 * Shows/hides the monitor component at the bottom of the merge tool.
	 * @param show true means to show the task monitor at the bottom of the merge tool.
	 */
	public void showMonitorComponent(boolean show) {
		if (show) {
			mergeTool.addStatusComponent(runManager.getMonitorComponent(), true, false);
		}
		else {
			mergeTool.removeStatusComponent(runManager.getMonitorComponent());
		}
	}

	/**
	 * Shows/hides the progress icon (spinning globe) at the bottom of the merge tool.
	 * @param show true means to show the icon.
	 */
	public void showProgressIcon(boolean show) {
		runManager.showProgressIcon(show);
	}

	/**
	 * Determines whether or not the user is being prompted to resolve a conflict.
	 * @return true if the user is being prompted for input.
	 */
	public synchronized boolean isPromptingUser() {
		return prompting;
	}

	/**
	 * Return whether the merge process has completed. (Needed for Junit testing
	 * only.)
	 */
	public boolean processingCompleted() {
		return mergeCompleted;
	}

	/**
	 * Called from the dialog when the "Apply" button is hit; call the 
	 * current MergeResolver's apply() method, and wake up the merge
	 * thread waiting on user input.
	 *
	 */
	synchronized void apply() {
		mergeResolvers[currentIndex].apply();
		inputReceived = true;
		notify();
		prompting = false;
	}

	/**
	 * Called from the dialog when the "Cancel" button is hit; call the 
	 * current MergeResolver's cancel() method, and wake up the merge
	 * thread waiting on user input.
	 *
	 */
	synchronized void cancel() {
		isCancelled = true;
		runManager.cancelAllRunnables();
		if (currentIndex < mergeResolvers.length) {
			mergeResolvers[currentIndex].cancel();
		}
		notify();
	}

	/**
	 * Schedule the next MergeResolver thread to run.
	 *
	 */
	private void scheduleMerge() {

		mergeMonitor.setProgress(currentIndex + 1);

		SwingUtilities.invokeLater(() -> {
			if (currentIndex < mergeResolvers.length && !isCancelled) {
				mergePlugin.updateMergeDescription(mergeResolvers[currentIndex].getDescription());
			}
		});

		MonitoredRunnable r = monitor -> {
			monitor.initialize(0);
			final String description = mergeResolvers[currentIndex].getDescription();
			monitor.setMessage(description); // The fire breathing dialog.
			mergeMonitor.setMessage(description); // The detail monitor at bottom right of merge tool.
			updateProgress(0, description); // The current phase progress area in the default merge panel.

			try {
				mergeResolvers[currentIndex].merge(monitor);
				if (mergeToolIsVisible) {
					showDefaultMergePanel(description);
				}
				++currentIndex;
				if (currentIndex == mergeResolvers.length || monitor.isCancelled()) {
					conflictsResolveCompleted();
				}
				else {
					// schedule next MergeResolver to run
					scheduleMerge();
				}

			}
			catch (final Exception e) {
				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						Msg.showError(this, null, "Error During Merge",
							"Error occurred in " + mergeResolvers[currentIndex].getName(), e);
					}
				});
				mergeStatus = false;
				conflictsResolveCompleted();
			}
		};

		if (currentIndex < mergeResolvers.length && !isCancelled) {
			runManager.runLater(r, mergeResolvers[currentIndex].getName(), 250);
		}
	}

	/**
	 * Display error message dialog in a blocking fashion.
	 * @param originator message originator
	 * @param title dialog title
	 * @param msg dialog message
	 */
	public static void displayErrorAndWait(Object originator, String title, String msg) {
		Swing.runNow(() -> Msg.showError(originator, null, title, msg));
	}

	/**
	 * Block until the user completes the current merge operation, or 
	 * cancels the merge process.
	 *
	 */
	protected synchronized void waitForInput() {
		for (;;) {
			if (isCancelled || inputReceived) {
				return;
			}
			try {
				prompting = true;
				wait();
			}
			catch (InterruptedException e) {
				// loop again
			}
		}
	}

	/**
	 * Called when all conflicts have been resolved, or the merge
	 * process was canceled; dismisses the merge tool which
	 * unblocks the initial merge thread.
	 *
	 */
	private void conflictsResolveCompleted() {
		if (mergeTool != null) {
			SwingUtilities.invokeLater(() -> {
				mergeTool.setVisible(false);
				if (mergePlugin != null) {
					mergePlugin.dispose();
				}
				mergeTool.exit(); // cleanup!
				mergeTool = null;
			});
		}
	}

//	/**
//	 * Returns the dimensions of the current merge tool.
//	 */
//	public Dimension getToolSize() {
//		if (mergeTool == null) {
//			return null;
//		}
//		return mergeTool.getSize();
//	}

//	/**
//	 * Sets the dimensions of the current merge tool.
//	 * @param dim the new dimensions
//	 */
//	public void setToolSize(Dimension dim) {
//		setToolSize(dim.width, dim.height);
//	}

//	/**
//	 * Sets the dimensions of the current merge tool.
//	 * @param width the new width of the merge tool.
//	 * @param height the new height of the merge tool.
//	 */
//	public void setToolSize(int width, int height) {
//		if (mergeTool == null) {
//			return;
//		}
//		mergeTool.setSize(width, height);
//	}

	/**
	 * Gets the resolve information object for the indicated standardized name.
	 * This is how information is passed between merge managers.
	 * <br>For example:
	 * <br>the data type merger knows what data type in the result is equivalent 
	 * to a given data type from my checked out program. The code unit and
	 * function mergers need to be able to get this information so they
	 * don't unknowingly re-introduce a data type that was already eliminated
	 * by a data type conflict.
	 * @param infoType the string indicating the type of resolve information
	 * @return the object for the named string or null
	 */
	public Object getResolveInformation(String infoType) {
		return resolveMap.get(infoType);
	}

	/**
	 * Sets the resolve information object for the indicated standardized name.
	 * This is how information is passed between merge managers.
	 * @param infoType the string indicating the type of resolve information
	 * @param infoObject the object for the named string. This information is
	 * determined by the merge manager that creates it.
	 * @see getResolveInformation(String)
	 */
	@Override
	public void setResolveInformation(String infoType, Object infoObject) {
		resolveMap.put(infoType, infoObject);
	}

	/**
	 * Returns the named merge resolver from the ones used directly by the MergeManager.
	 * @param name the name of the desired merge resolver
	 * @return the merge resolver or null.
	 */
	public MergeResolver getMergeResolverByName(String name) {
		for (MergeResolver mergeMgr : mergeResolvers) {
			if (name.equals(mergeMgr.getName())) {
				return mergeMgr;
			}
		}
		return null;
	}

	/**
	 * For Junit tests
	 * @return the merge tool
	 */
	public PluginTool getMergeTool() {
		return mergeTool;
	}

	/**
	 * Determines if the modal merge tool is currently displayed on the screen.
	 * @return true if the merge tool is displayed.
	 */
	public boolean isMergeToolVisible() {
		return mergeToolIsVisible;
	}

	/**
	 * gets the default merge progress panel that indicates all the phases and their current status.
	 * @return the merge panel that indicates progress.
	 */
	public MergeProgressPanel getMergeProgressPanel() {
		return mergeProgressPanel;
	}

	/**
	 * Gets the TaskMonitor component that is displayed at the bottom of the merge tool.
	 * @return the task monitor component.
	 */
	public JComponent getMonitorComponent() {
		return runManager.getMonitorComponent();
	}

	/**
	 * Updates the current phase progress area in the default merge panel.
	 * @param description a message describing what is currently occurring in this phase.
	 * Null indicates to use the default message.
	 */
	@Override
	public void updateProgress(final String description) {
		SwingUtilities.invokeLater(() -> {
			if (!isCancelled) {
				mergePlugin.updateProgressDetails(description);
			}
		});
	}

	/**
	 * Updates the current phase progress area in the default merge panel.
	 * @param currentProgressPercentage the progress percentage completed for the current phase.
	 * This should be a value from 0 to 100.
	 */
	@Override
	public void updateProgress(final int currentProgressPercentage) {
		if (currentProgressPercentage < 0 || currentProgressPercentage > 100) {
			System.out.println("Invalid progress value (" + currentProgressPercentage +
				"). Must be from 0 to 100.");
			return;
		}
		SwingUtilities.invokeLater(() -> {
			if (!isCancelled) {
				mergePlugin.setCurrentProgress(currentProgressPercentage);
			}
		});
	}

	/**
	 * Updates the current phase progress area in the default merge panel.
	 * @param currentProgressPercentage the progress percentage completed for the current phase.
	 * This should be a value from 0 to 100.
	 * @param progressMessage a message indicating what is currently occurring in this phase.
	 */
	@Override
	public void updateProgress(final int currentProgressPercentage, final String progressMessage) {
		SwingUtilities.invokeLater(() -> {
			if (!isCancelled) {
				mergePlugin.setCurrentProgress(currentProgressPercentage);
				mergePlugin.updateProgressDetails(progressMessage);
			}
		});
	}

	/**
	 * The manager (MergeResolver) for a particular merge phase should call this when its phase or sub-phase begins.
	 * The string array should match one that the returned by MergeResolver.getPhases().
	 * @param mergePhase identifier for the merge phase to change to in progress status.
	 * @see MergeResolver
	 */
	@Override
	public void setInProgress(String[] mergePhase) {
		mergeProgressPanel.setInProgress(mergePhase);
	}

	/**
	 * The manager (MergeResolver) for a particular merge phase should call this when its phase or sub-phase completes.
	 * The string array should match one that the returned by MergeResolver.getPhases().
	 * @param mergePhase identifier for the merge phase to change to completed status.
	 * @see MergeResolver
	 */
	@Override
	public void setCompleted(String[] mergePhase) {
		mergeProgressPanel.setCompleted(mergePhase);
		updateProgress(0, "");
		mergeMonitor.setMessage("");
		mergeMonitor.setProgress(0);
	}
}
