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
package ghidra.app.plugin.core.misc;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileNotFoundException;
import java.util.*;

import javax.swing.Timer;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.FrontEndOnly;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.*;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.util.bean.opteditor.OptionsVetoException;
import ghidra.util.exception.AssertException;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Generates recovery snapshot files",
	description = "Facilitates the periodic creation of recovery snapshot files.  " +
			"In the event of a crash or application hang, these files may be used to " +
			"recover any un-saved file changes at the time of failure.  The frequency " +
			"in which these snapshots are generated is controlled via a Front-end " +
			"Recovery Option."
)
//@formatter:on
public class RecoverySnapshotMgrPlugin extends Plugin
		implements FrontEndOnly, OptionsChangeListener, ProjectListener {

	private final static String OPTIONS_TITLE = "Recovery";
	private final static String SNAPSHOT_PERIOD_OPTION = "Snapshot period (minutes, 0=disabled)";

	private static final int DELAYED_RETRY_PERIOD_MSEC = 10000;  // 10 seconds
	private int snapshotPeriodMin = 5; // default period = 5 minutes

	private Project currentProject;
	private DomainFolderChangeListener fileListener;
	private ActionListener snapshotAction;
	private Timer timer;
	private long timerStart = -1;
	private int totalDelayTime;
	private SnapshotTask snapshotTask = new SnapshotTask();

	private Set<DomainFile> fileSet = new HashSet<>();
	private TreeSet<DomainFile> pendingSnapshotSet = new TreeSet<>();

	/**
	  * Constructor - Setup the plugin
	  */
	public RecoverySnapshotMgrPlugin(PluginTool tool) {
		super(tool);

		if (tool instanceof FrontEndTool) {
			initSnapshotOptions();
		}
	}

	@Override
	protected void init() {

		fileListener = new DomainFolderListenerAdapter() {
			@Override
			public void domainFileObjectOpenedForUpdate(DomainFile file, DomainObject object) {
				addFile(file);
			}

			@Override
			public void domainFileObjectClosed(DomainFile file, DomainObject object) {
				removeFile(file);
			}

		};

		snapshotAction = new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				synchronized (this) {
					if (pendingSnapshotSet.isEmpty()) {
						pendingSnapshotSet.addAll(fileSet);
						startSnapshotTimer(false);
						return;
					}
				}
				(new Thread(snapshotTask, "recovery-snapshot-task")).start();
			}
		};

		FrontEndTool feTool = (FrontEndTool) tool;
		feTool.addProjectListener(this);
		Project prj = feTool.getProject();
		if (prj != null) {
			projectOpened(prj);
			findOpenFiles();
		}

		reportTimerSetting();
	}

	/**
	 * Initialize the look and feel options.
	 */
	private void initSnapshotOptions() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		opt.registerOption(SNAPSHOT_PERIOD_OPTION, snapshotPeriodMin, null,
			"The time before creating an auto-save of a program");
		snapshotPeriodMin = opt.getInt(SNAPSHOT_PERIOD_OPTION, snapshotPeriodMin);
		if (snapshotPeriodMin < 0) {
			opt.setInt(SNAPSHOT_PERIOD_OPTION, 0);
			snapshotPeriodMin = 0;
		}

		opt.addOptionsChangeListener(this);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(SNAPSHOT_PERIOD_OPTION)) {
			synchronized (this) {
				int oldSnapshotPeriod = snapshotPeriodMin;
				int newSnapshotPeriodMin =
					options.getInt(SNAPSHOT_PERIOD_OPTION, snapshotPeriodMin);
				if (newSnapshotPeriodMin < 0) {
					throw new OptionsVetoException("The snapshot period must be >= 0");
				}
				snapshotPeriodMin = newSnapshotPeriodMin;
				if (oldSnapshotPeriod != snapshotPeriodMin) {
					reportTimerSetting();
					if (oldSnapshotPeriod == 0 || timerStart > 0) {
						// Fix current running timer
						if (snapshotPeriodMin > 0 && timerStart > 0) {
							totalDelayTime = (int) ((new Date()).getTime() - timerStart);
						}
						startSnapshotTimer(false);
					}
				}
			}
		}
	}

	private void reportTimerSetting() {
		if (snapshotPeriodMin == 0) {
			Msg.debug(this, "Recovery snapshot timer disabled!");
		}
		else {
			Msg.debug(this, "Recovery snapshot timer set to " + snapshotPeriodMin + " minute(s)");
		}
	}

	/**
	 * Tells a plugin that it is no longer needed.  The plugin should remove itself
	 * from anything that it is registered to and release any resources.  Also,
	 * any plugin that overrides this method should call super.dispose().
	 */
	@Override
	public void dispose() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		opt.removeOptionsChangeListener(this);
		super.dispose();
	}

	@Override
	public synchronized void projectOpened(Project project) {
		if (project == currentProject) {
			return;
		}
		if (currentProject != null) {
			throw new AssertException("Unexpected - two or more projects active");
		}
		currentProject = project;
		findOpenFiles();
		currentProject.getProjectData().addDomainFolderChangeListener(fileListener);
		startSnapshotTimer(false);
	}

	@Override
	public synchronized void projectClosed(Project project) {
		if (currentProject != null) {
			stopSnapshotTimer();
			currentProject.getProjectData().removeDomainFolderChangeListener(fileListener);
			pendingSnapshotSet.clear();
			fileSet.clear();
			currentProject = null;
		}
	}

	private void findOpenFiles() {
		ArrayList<DomainFile> list = new ArrayList<>();
		currentProject.getProjectData().findOpenFiles(list);
		for (DomainFile df : list) {
			addFile(df);
		}
	}

	private synchronized void addFile(DomainFile df) {
		if (df.isInWritableProject()) {
			fileSet.add(df);
			if (totalDelayTime == 0) {
				pendingSnapshotSet.add(df);
			}
		}
	}

	private synchronized void removeFile(DomainFile df) {
		if (df.isInWritableProject()) {
			fileSet.remove(df);
			pendingSnapshotSet.remove(df);
		}
	}

	private synchronized void stopSnapshotTimer() {
		if (timer != null) {
			timer.stop();
		}
		timerStart = -1;
	}

	private synchronized void startSnapshotTimer(boolean retryPeriod) {
		stopSnapshotTimer();
		if (snapshotPeriodMin == 0) {
			totalDelayTime = 0;
			return;
		}
		int msec = DELAYED_RETRY_PERIOD_MSEC;
		if (retryPeriod) {
			totalDelayTime += msec;
			if (totalDelayTime >= (snapshotPeriodMin * 60000)) {
				// Retry time has exceeded normal snapshot period - switch mode
				retryPeriod = false;
			}
		}
		else {
			// Reduce period to compensate for delayed snapshot
			totalDelayTime -= (snapshotPeriodMin * 60000);
			if (totalDelayTime < -DELAYED_RETRY_PERIOD_MSEC) {
				msec = -totalDelayTime;
			}
		}
		if (!retryPeriod) {
			pendingSnapshotSet.clear();
			pendingSnapshotSet.addAll(fileSet);
			totalDelayTime = 0;
			timerStart = (new Date()).getTime();
		}
		if (timer == null) {
			timer = new Timer(msec, snapshotAction);
			timer.setRepeats(false);
			timer.start();
		}
		else {
			timer.setInitialDelay(msec);
			timer.restart();
		}
	}

	private class SnapshotTask implements Runnable {

		public SnapshotTask() {
		}

		@Override
		public void run() {

			ArrayList<DomainFile> unhandledList = new ArrayList<>();
			DomainFile df = null;
			while (true) {
				synchronized (RecoverySnapshotMgrPlugin.this) {
					if (pendingSnapshotSet.isEmpty()) {
						break;
					}
					df = pendingSnapshotSet.first();
					pendingSnapshotSet.remove(df);
				}
				boolean completed = false;
				try {
					completed = df.takeRecoverySnapshot();
				}
				catch (FileNotFoundException e) {
					// file was removed after snapshot was scheduled - ignore
					completed = true;
				}
				catch (Throwable t) {
					completed = true; // no point in trying again!
					Msg.showError(this, null, "Recovery Snapshot Error",
						"Failed to generate recovery snapshot for: " + df.getName(), t);
				}
				if (!completed && fileSet.contains(df)) {
					unhandledList.add(df);
				}
			}

			synchronized (RecoverySnapshotMgrPlugin.this) {
				if (!unhandledList.isEmpty()) {
					pendingSnapshotSet.clear();
					pendingSnapshotSet.addAll(unhandledList);
					startSnapshotTimer(true);
				}
				else {
					startSnapshotTimer(false);
				}
			}

		}
	}

}
