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

import java.net.URL;
import java.rmi.NoSuchObjectException;
import java.util.*;

import org.jdom.Element;

import ghidra.app.events.*;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.*;
import ghidra.app.util.task.OpenProgramTask;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.TransientToolState;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskLauncher;

class MultiProgramManager implements DomainObjectListener, TransactionListener {

	private static int nextProgramInfoInstance = 0;

	private ProgramManagerPlugin plugin;
	private PluginTool tool;
	private ArrayList<ProgramInfo> openProgramList;
	private HashMap<Program, ProgramInfo> programMap;
	private ProgramInfo currentInfo;
	private TransactionMonitor txMonitor;
	private MyFolderListener folderListener;
	private Runnable programChangedRunnable;

	MultiProgramManager(ProgramManagerPlugin programManagerPlugin) {
		this.plugin = programManagerPlugin;
		this.tool = programManagerPlugin.getTool();
		openProgramList = new ArrayList<>();
		programMap = new HashMap<>();
		txMonitor = new TransactionMonitor();
		txMonitor.setName("Transaction Open (Program being modified)");
		tool.addStatusComponent(txMonitor, true, true);
		folderListener = new MyFolderListener();
		tool.getProject().getProjectData().addDomainFolderChangeListener(folderListener);

		programChangedRunnable = () -> {
			if (tool == null) {
				return; // we have been disposed
			}
			plugin.updateProgramActions();
		};
	}

	void addProgram(Program p, URL ghidraURL, int state) {
		ProgramInfo oldInfo = programMap.get(p);
		if (oldInfo == null) {
			p.addConsumer(tool);
			ProgramInfo info = new ProgramInfo(p, state != ProgramManager.OPEN_HIDDEN);
			info.ghidraURL = ghidraURL;
			openProgramList.add(info);
			Collections.sort(openProgramList);
			programMap.put(p, info);

			fireOpenEvents(p);

			p.addListener(this);
			p.addTransactionListener(this);
		}
		else {
			if (!oldInfo.visible && state != ProgramManager.OPEN_HIDDEN) {
				oldInfo.setVisible(true);
			}
		}
		if (state == ProgramManager.OPEN_CURRENT) {
			saveLocation();
			setCurrentProgram(p);
		}
	}

	void dispose() {
		tool.getProject().getProjectData().removeDomainFolderChangeListener(folderListener);
		fireActivatedEvent(null);
		Iterator<Program> it = programMap.keySet().iterator();
		while (it.hasNext()) {
			Program p = it.next();
			p.removeListener(this);
			p.removeTransactionListener(this);
			fireCloseEvents(p);
			p.release(tool);
		}
		programMap.clear();
		openProgramList.clear();
		tool.setSubTitle("");
		tool.removeStatusComponent(txMonitor);
		tool = null;
		plugin = null;
	}

	void removeProgram(Program p) {
		ProgramInfo info = programMap.get(p);
		if (info != null) {
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
				openProgramList.remove(info);
				if (info == currentInfo) {
					ProgramInfo newCurrent = findNextCurrent();
					setCurrentProgram(newCurrent);
				}
				fireCloseEvents(p);
				p.release(tool);
				if (openProgramList.isEmpty()) {
					plugin.getTool().clearLastEvents();
				}
			}
		}
	}

	private ProgramInfo findNextCurrent() {
		Iterator<ProgramInfo> iter = openProgramList.iterator();
		while (iter.hasNext()) {
			ProgramInfo pi = iter.next();
			if (pi.visible) {
				return pi;
			}
		}
		return null;
	}

	Program[] getOtherPrograms() {
		Program currentProgram = getCurrentProgram();
		ArrayList<Program> list = new ArrayList<>();
		int size = openProgramList.size();
		for (int index = 0; index < size; index++) {
			Program program = openProgramList.get(index).program;
			if (currentProgram != program) {
				list.add(program);
			}
		}
		return list.toArray(new Program[list.size()]);
	}

	Program[] getAllPrograms() {
		Program[] programs = new Program[openProgramList.size()];
		for (int i = 0; i < programs.length; i++) {
			programs[i] = (openProgramList.get(i)).program;
		}
		return programs;
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

		ProgramInfo info = programMap.get(p);
		if (info != null) {
			setCurrentProgram(info);
		}
	}

	Program getProgram(Address addr) {
		Iterator<ProgramInfo> it = openProgramList.iterator();
		while (it.hasNext()) {
			ProgramInfo pi = it.next();
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
			DomainFile df = currentInfo.program.getDomainFile();
			String title = df.toString();
			if (df.isReadOnly()) {
				title = title + " [Read-Only]";
			}
			tool.setSubTitle(title);
			txMonitor.setProgram(currentInfo.program);
			if (currentInfo.lastState != null) {
				toolState = currentInfo.lastState;
			}
		}
		fireActivatedEvent(newProgram);
		if (toolState != null) {
			toolState.restoreTool();
		}
	}

	/**
	 * @param program
	 */
	private void fireOpenEvents(Program program) {
		plugin.firePluginEvent(new ProgramOpenedPluginEvent("", program));
		plugin.firePluginEvent(new OpenProgramPluginEvent("", program));
	}

	/**
	 * @param program
	 */
	private void fireCloseEvents(Program program) {
		plugin.firePluginEvent(new ProgramClosedPluginEvent("", program));
		plugin.firePluginEvent(new CloseProgramPluginEvent("", program, true));
//		tool.contextChanged();
	}

	/**
	 * @param p
	 */
	private void fireActivatedEvent(Program newProgram) {
		plugin.firePluginEvent(new ProgramActivatedPluginEvent("", newProgram));
	}

	private void fireVisibilityChangeEvent(Program program, boolean isVisible) {
		plugin.firePluginEvent(new ProgramVisibilityChangePluginEvent("", program, isVisible));
	}

	/**
	 * @see ghidra.framework.model.DomainObjectListener#domainObjectChanged(ghidra.framework.model.DomainObjectChangedEvent)
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (!(ev.getSource() instanceof Program)) {
			return;
		}
		Program program = (Program) ev.getSource();
		if (ev.containsEvent(DomainObject.DO_DOMAIN_FILE_CHANGED) ||
			ev.containsEvent(DomainObject.DO_OBJECT_ERROR)) {
			for (int i = 0; i < ev.numRecords(); i++) {
				DomainObjectChangeRecord docr = ev.getChangeRecord(i);
				int eventType = docr.getEventType();
				if (eventType == DomainObject.DO_DOMAIN_FILE_CHANGED) {
					if (currentInfo != null && currentInfo.program == program) {
						String name = program.getDomainFile().toString();
						tool.setSubTitle(name);
					}
				}
				else if (eventType == DomainObject.DO_OBJECT_ERROR) {
					String msg;
					Throwable t = (Throwable) docr.getNewValue();
					if (t instanceof NoSuchObjectException) {
						msg = program.getName() + " was closed due to an unrecoverable error!" +
							"\nThis error could be the result of your computer becoming suspended" +
							"\nor sleeping allowing the network connection with the Ghidra Server" +
							"\nto fail.";
					}
					else {
						msg = program.getName() + " was closed due to an unrecoverable error!" +
							"\n \nSuch failures are generally due to an IO Error caused" +
							"\nby the local filesystem or server.";
					}

					//abort();
					Msg.showError(this, tool.getToolFrame(), "Severe Error Condition", msg);
					removeProgram(program);
					return;
				}

			}
		}
	}

	/**
	 * @return
	 */
	public boolean isEmpty() {
		return openProgramList.isEmpty();
	}

	/**
	 * @param program
	 * @return
	 */
	public boolean contains(Program program) {
		return programMap.containsKey(program);
	}

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
			OpenProgramTask openTask = new OpenProgramTask(file, -1, this);
			openTask.setSilent();
//			OpenDomainFileTask openTask = new OpenDomainFileTask(file, -1, tool, 
//					plugin, true, dataState != null ? ProgramManager.OPEN_CURRENT : ProgramManager.OPEN_VISIBLE);
			new TaskLauncher(openTask, tool.getToolFrame());
			Program openProgram = openTask.getOpenProgram();
			plugin.openProgram(openProgram,
				dataState != null ? ProgramManager.OPEN_CURRENT : ProgramManager.OPEN_VISIBLE);
			openProgram.release(this);
			removeProgram((Program) oldObject);
			if (dataState != null) {
				tool.restoreDataStateFromXml(dataState);
			}
		}
	}

	boolean isVisible(Program program) {
		ProgramInfo info = programMap.get(program);
		return info != null ? info.visible : false;
	}

	void releaseProgram(Program program, Object owner) {
		ProgramInfo info = programMap.get(program);
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
		ProgramInfo info = programMap.get(program);
		if (info != null && info.owner == null) {
			info.owner = owner;
			return true;
		}
		return false;
	}

	public boolean isPersistent(Program program) {
		ProgramInfo info = programMap.get(program);
		return (info != null && info.owner != null);
	}

	private class ProgramInfo implements Comparable<ProgramInfo> {

		Program program;
		URL ghidraURL;
		TransientToolState lastState;
		private int instance;
		boolean visible;
		Object owner;

		ProgramInfo(Program p, boolean visible) {
			this.program = p;
			this.visible = visible;
			synchronized (ProgramInfo.class) {
				instance = ++nextProgramInfoInstance;
			}
		}

		public void setVisible(boolean state) {
			visible = state;
			fireVisibilityChangeEvent(program, visible);
		}

		@Override
		public int compareTo(ProgramInfo info) {
			return instance - info.instance;
		}
	}

	@Override
	public void transactionEnded(DomainObjectAdapterDB domainObj) {
		// don't care
	}

	@Override
	public void transactionStarted(DomainObjectAdapterDB domainObj, Transaction tx) {
		// don't care
	}

	@Override
	public void undoRedoOccurred(DomainObjectAdapterDB domainObj) {
		// don't care
	}

	@Override
	public void undoStackChanged(DomainObjectAdapterDB domainObj) {
		SystemUtilities.runSwingLater(programChangedRunnable);
	}

	public Program getOpenProgram(URL ghidraURL) {
		if (!GhidraURL.isServerRepositoryURL(ghidraURL)) {
			return null;
		}
		URL normalizedURL = GhidraURL.getNormalizedURL(ghidraURL);
		for (ProgramInfo info : programMap.values()) {
			URL url = info.ghidraURL;
			if (url != null && url.equals(normalizedURL)) {
				return info.program;
			}
		}
		return null;
	}

	public Program getOpenProgram(DomainFile domainFile, int version) {
		for (Program program : programMap.keySet()) {
			DomainFile programDomainFile = program.getDomainFile();
			if (filesMatch(domainFile, version, programDomainFile)) {
				return program;
			}
		}
		return null;
	}

	private boolean filesMatch(DomainFile file, int version, DomainFile openFile) {
		if (!file.getPathname().equals(openFile.getPathname())) {
			return false;
		}

		if (file.isCheckedOut() != openFile.isCheckedOut()) {
			return false;
		}

		if (!SystemUtilities.isEqual(file.getProjectLocator(), openFile.getProjectLocator())) {
			return false;
		}

		int openVersion = openFile.isReadOnly() ? openFile.getVersion() : -1;
		return version == openVersion;
	}
}
