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

import java.rmi.NoSuchObjectException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.jdom.Element;

import ghidra.app.events.*;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.*;
import ghidra.app.util.task.OpenProgramRequest;
import ghidra.app.util.task.OpenProgramTask;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.TransientToolState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.TaskLauncher;

/**
 * Class for tracking open programs in the tool.
 */
class MultiProgramManager implements DomainObjectListener, TransactionListener {

	private ProgramManagerPlugin plugin;
	private PluginTool tool;
	private ProgramInfo currentInfo;
	private TransactionMonitor txMonitor;
	private MyFolderListener folderListener;

	private Runnable programChangedRunnable;
	private boolean hasUnsavedPrograms;
	private String pluginName;

	// This data structure is accessed from multiple threads.  Rather than synchronizing all
	// accesses, we have chosen to be weakly consistent.   We assume that any out-of-date checks
	// for open program state will be self-correcting.  For example, if a client checks to see if
	// a program is open before opening it, then a repeated call to open the program will not
	// result in a second copy of that program being opened.  This is safe because program opens
	// and closes are all done from the Swing thread.
	private Map<Program, ProgramInfo> programMap = new ConcurrentHashMap<>();

	MultiProgramManager(ProgramManagerPlugin programManagerPlugin) {
		this.plugin = programManagerPlugin;
		this.tool = programManagerPlugin.getTool();
		this.pluginName = plugin.getName();

		txMonitor = new TransactionMonitor();
		txMonitor.setName("Transaction Open (Program being modified)");
		tool.addStatusComponent(txMonitor, true, true);
		folderListener = new MyFolderListener();
		tool.getProject().getProjectData().addDomainFolderChangeListener(folderListener);

		programChangedRunnable = () -> {
			if (tool == null) {
				return; // we have been disposed
			}
			hasUnsavedPrograms = checkForUnsavedPrograms();
			plugin.contextChanged();
		};
	}

	void addProgram(Program p, ProgramLocator locator, int state) {
		addProgram(new ProgramInfo(p, locator, state != ProgramManager.OPEN_HIDDEN), state);
	}

	private void addProgram(ProgramInfo programInfo, int state) {
		Program p = programInfo.program;
		ProgramInfo oldInfo = getInfo(p);
		if (oldInfo == null) {
			oldInfo = programInfo;
			p.addConsumer(tool);
			programMap.put(p, oldInfo);

			fireOpenEvents(p);

			p.addListener(this);
			p.addTransactionListener(this);
		}
		else if (!oldInfo.visible && state != ProgramManager.OPEN_HIDDEN) {
			oldInfo.setVisible(true);
		}
		if (state == ProgramManager.OPEN_CURRENT) {
			saveLocation();
			setCurrentProgram(p);
		}
	}

	void dispose() {
		tool.getProject().getProjectData().removeDomainFolderChangeListener(folderListener);
		fireActivatedEvent(null);

		for (Program p : programMap.keySet()) {
			p.removeListener(this);
			p.removeTransactionListener(this);
			fireCloseEvents(p);
			p.release(tool);
		}
		programMap.clear();
		tool.setSubTitle("");
		tool.removeStatusComponent(txMonitor);
		tool = null;
		plugin = null;
	}

	void removeProgram(Program p) {
		ProgramInfo info = getInfo(p);
		if (info == null) {
			return;
		}

		if (info.owner != null) {
			// persist program
			info.setVisible(false);
			if (info == currentInfo) {
				ProgramInfo newCurrent = findNextCurrent();
				setCurrentProgram(newCurrent);
			}
		}
		else {
			p.removeTransactionListener(this);
			programMap.remove(p);
			p.removeListener(this);
			if (info == currentInfo) {
				ProgramInfo newCurrent = findNextCurrent();
				setCurrentProgram(newCurrent);
			}
			fireCloseEvents(p);
			p.release(tool);
			if (programMap.isEmpty()) {
				plugin.getTool().clearLastEvents();
			}
		}
	}

	private ProgramInfo findNextCurrent() {
		for (ProgramInfo pi : getSortedProgramInfos()) {
			if (pi.visible) {
				return pi;
			}
		}
		return null;
	}

	List<Program> getOtherPrograms() {
		List<Program> otherPrograms = new ArrayList<>(programMap.keySet());
		otherPrograms.remove(getCurrentProgram());
		return otherPrograms;
	}

	List<Program> getAllPrograms() {
		List<ProgramInfo> sorted = getSortedProgramInfos();
		return sorted.stream().map(info -> info.program).collect(Collectors.toList());
	}

	Program getCurrentProgram() {
		if (currentInfo != null) {
			return currentInfo.program;
		}
		return null;
	}

	void setCurrentProgram(Program p) {
		if (currentInfo != null) {
			if (currentInfo.program.equals(p)) {
				return; // already active
			}
		}

		if (p == null) {
			return;
		}

		ProgramInfo info = getInfo(p);
		if (info != null) {
			setCurrentProgram(info);
		}
	}

	Program getProgram(Address addr) {
		for (ProgramInfo pi : getSortedProgramInfos()) {
			if (pi.program.getMemory().contains(addr)) {
				return pi.program;
			}
		}
		return null;
	}

	void saveLocation() {
		NavigationHistoryService historyService = tool.getService(NavigationHistoryService.class);
		if (historyService == null) {
			return;
		}
		GoToService gotoService = tool.getService(GoToService.class);
		if (gotoService == null) {
			return;
		}
		Navigatable defaultNavigatable = gotoService.getDefaultNavigatable();
		if (defaultNavigatable == null || defaultNavigatable.getProgram() == null) {
			return;
		}
		historyService.addNewLocation(defaultNavigatable);
	}

	private List<ProgramInfo> getSortedProgramInfos() {
		List<ProgramInfo> list = new ArrayList<>(programMap.values());
		Collections.sort(list);
		return list;

	}

	private void setCurrentProgram(ProgramInfo info) {
		if (currentInfo == info) {
			return;
		}

		Program newProgram = info == null ? null : info.program;

		if (currentInfo != null) {
			currentInfo.lastState = tool.getTransientState();
			tool.setSubTitle("");
			txMonitor.setProgram(null);
		}
		currentInfo = info;
		TransientToolState toolState = null;
		if (currentInfo != null) {
			currentInfo.setVisible(true);
			tool.setSubTitle(currentInfo.toString());
			txMonitor.setProgram(currentInfo.program);
			if (currentInfo.lastState != null) {
				toolState = currentInfo.lastState;
			}
		}
		fireActivatedEvent(newProgram);
		if (toolState != null) {
			toolState.restoreTool();
		}
		// only fire the post activated event when a program is activated (we send activated with
		// null program to represent a phantom de-activated event)
		if (newProgram != null) {
			firePostActivatedEvent(newProgram);
		}
	}

	private void fireOpenEvents(Program program) {
		plugin.firePluginEvent(new ProgramOpenedPluginEvent(pluginName, program));
		plugin.firePluginEvent(new OpenProgramPluginEvent(pluginName, program));
	}

	private void fireCloseEvents(Program program) {
		plugin.firePluginEvent(new ProgramClosedPluginEvent(pluginName, program));
		plugin.firePluginEvent(new CloseProgramPluginEvent(pluginName, program, true));
//		tool.contextChanged();
	}

	private void fireActivatedEvent(Program newProgram) {
		plugin.firePluginEvent(new ProgramActivatedPluginEvent(pluginName, newProgram));
	}

	private void firePostActivatedEvent(Program newProgram) {
		plugin.firePluginEvent(new ProgramPostActivatedPluginEvent(pluginName, newProgram));
	}

	private void fireVisibilityChangeEvent(Program program, boolean isVisible) {
		plugin.firePluginEvent(
			new ProgramVisibilityChangePluginEvent(pluginName, program, isVisible));
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (!(ev.getSource() instanceof Program program)) {
			return;
		}

		ev.forEach(DomainObjectEvent.FILE_CHANGED, r -> {
			ProgramInfo info = getInfo(program);
			if (info != null) {
				info.programSavedAs(); // updates info to new domain file
			}
			if (currentInfo != null && currentInfo.program == program) {
				String name = program.getDomainFile().toString();
				tool.setSubTitle(name);
			}
		});

		if (ev.contains(DomainObjectEvent.ERROR)) {
			for (DomainObjectChangeRecord docr : ev) {
				EventType eventType = docr.getEventType();
				if (eventType == DomainObjectEvent.ERROR) {
					String msg = getErrorMessage(program, (Throwable) docr.getNewValue());
					Msg.showError(this, tool.getToolFrame(), "Severe Error Condition", msg);
					removeProgram(program);
					return;
				}
			}
		}
	}

	private String getErrorMessage(Program program, Throwable t) {
		if (t instanceof NoSuchObjectException) {
			return program.getName() + " was closed due to an unrecoverable error!" +
				"\nThis error could be the result of your computer becoming suspended" +
				"\nor sleeping allowing the network connection with the Ghidra Server" +
				"\nto fail.";
		}
		return program.getName() + " was closed due to an unrecoverable error!" +
			"\n \nSuch failures are generally due to an IO Error caused" +
			"\nby the local filesystem or server.";
	}

	public boolean isEmpty() {
		return programMap.isEmpty();
	}

	public boolean contains(Program p) {
		if (p == null) {
			return false;
		}
		return programMap.containsKey(p);
	}

	boolean isVisible(Program p) {
		ProgramInfo info = getInfo(p);
		return info != null ? info.visible : false;
	}

	void releaseProgram(Program program, Object owner) {
		ProgramInfo info = getInfo(program);
		if (info != null && info.owner == owner) {
			info.owner = null;
			if (!info.visible) {
				if (program.isChanged()) {
					info.setVisible(true);
				}
				plugin.closeProgram(program, false);
			}
			else if (program.isTemporary()) {
				plugin.closeProgram(program, false);
			}
		}
	}

	boolean setPersistentOwner(Program program, Object owner) {
		ProgramInfo info = getInfo(program);
		if (info != null && info.owner == null) {
			info.owner = owner;
			return true;
		}
		return false;
	}

	boolean isPersistent(Program p) {
		ProgramInfo info = getInfo(p);
		return (info != null && info.owner != null);
	}

	ProgramInfo getInfo(Program p) {
		if (p == null) {
			return null;
		}
		return programMap.get(p);
	}

	Program getOpenProgram(ProgramLocator programLocator) {
		for (ProgramInfo info : programMap.values()) {
			if (info.getProgramLocator().equals(programLocator)) {
				return info.program;
			}
		}
		return null;
	}

	/**
	 * Returns true if there is at least one program that has unsaved changes.
	 * @return true if there is at least one program that has unsaved changes.
	 */
	boolean hasUnsavedPrograms() {
		return hasUnsavedPrograms;
	}

	private boolean checkForUnsavedPrograms() {
		// first check the current program as that is the one most likely to have changes
		Program currentProgram = getCurrentProgram();
		if (currentProgram != null && currentProgram.isChanged()) {
			return true;
		}
		// look at all the open programs to see if any have changes
		for (ProgramInfo programInfo : programMap.values()) {
			if (programInfo.program.isChanged()) {
				return true;
			}
		}
		return false;

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
	public void undoRedoOccurred(DomainObjectAdapterDB domainObj) {
		// don't care
	}

	@Override
	public void undoStackChanged(DomainObjectAdapterDB domainObj) {
		Swing.runLater(programChangedRunnable);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	private class MyFolderListener extends DomainFolderListenerAdapter {

		@Override
		public void domainFileObjectReplaced(DomainFile file, DomainObject oldObject) {

			/**
			 * Special handling for when a file is checked-in.  The existing program has be moved
			 * to a proxy file (no longer in the project) so that it can be closed and the program
			 * re-opened with the new version after the check-in merge.
			 */

			if (!programMap.containsKey(oldObject)) {
				return;
			}
			Element dataState = null;
			if (currentInfo != null && currentInfo.program == oldObject) {
				// save dataState as though the project state was saved and re-opened to simulate
				// recovering after closing the program during this swap
				dataState = tool.saveDataStateToXml(true);
			}
			OpenProgramTask openTask = new OpenProgramTask(file, DomainFile.DEFAULT_VERSION, this);
			openTask.setSilent();
			new TaskLauncher(openTask, tool.getToolFrame());
			OpenProgramRequest openProgramReq = openTask.getOpenProgram();
			if (openProgramReq != null) {
				plugin.openProgram(openProgramReq.getProgram(),
					dataState != null ? ProgramManager.OPEN_CURRENT : ProgramManager.OPEN_VISIBLE);
				openProgramReq.release();
				removeProgram((Program) oldObject);
				if (dataState != null) {
					tool.restoreDataStateFromXml(dataState);
				}
			}
		}
	}

	class ProgramInfo implements Comparable<ProgramInfo> {

		// arbitrary counter for given ProgramInfo objects and ID to use for sorting
		private static final AtomicInteger nextAvailableId = new AtomicInteger();

		public final Program program;
		public ProgramLocator programLocator;

		private TransientToolState lastState;
		private int instance;
		private boolean visible = false;
		private Object owner;

		private String displayName; // cached displayName

		ProgramInfo(Program p, ProgramLocator programLocator, boolean visible) {
			this.program = p;
			this.programLocator = programLocator;
			this.visible = visible;
			instance = nextAvailableId.incrementAndGet();
		}

		ProgramLocator getProgramLocator() {
			return programLocator;
		}

		void programSavedAs() {
			programLocator = new ProgramLocator(program.getDomainFile());
			displayName = null;
		}

		public void setVisible(boolean state) {
			visible = state;
			fireVisibilityChangeEvent(program, visible);
		}

		@Override
		public int compareTo(ProgramInfo info) {
			return instance - info.instance;
		}

		@Override
		public String toString() {
			if (displayName != null) {
				return displayName;
			}
			StringBuilder buf = new StringBuilder();
			DomainFile df = program.getDomainFile();
			buf.append(program.getDomainFile().toString());
			if (df.isReadOnly()) {
				buf.append(" [Read-Only]");
			}
			displayName = buf.toString();
			return displayName;
		}

		public boolean canReopen() {
			return programLocator.canReopen();
		}
	}
}
