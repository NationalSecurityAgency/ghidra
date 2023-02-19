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
package ghidra.app.plugin.core.reloc;

import docking.action.DockingAction;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.GoToService;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.TaskMonitor;
import ghidra.util.worker.Job;
import ghidra.util.worker.Worker;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Displays relocation information",
	description = "This plugin provides a component for displaying the reloction table. "
			+ "The table can be used to navigate in the code browser.",
	servicesRequired = { GoToService.class },
	eventsProduced = { ProgramLocationPluginEvent.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class RelocationTablePlugin extends Plugin implements DomainObjectListener {

	private Program currentProgram;
	private RelocationProvider provider;

	/**
	 * A worker that will process domain object change event work off of the Swing thread.
	 */
	private Worker domainObjectWorker = Worker.createGuiWorker();

	public RelocationTablePlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		provider = new RelocationProvider(this);
		createActions();
	}

	private void createActions() {

		DockingAction selectAction = new MakeProgramSelectionAction(this, provider.getTable());
		tool.addLocalAction(provider, selectAction);

		DockingAction navigationAction = new SelectionNavigationAction(this, provider.getTable());
		tool.addLocalAction(provider, navigationAction);
	}

	@Override
	public void dispose() {
		super.dispose();
		provider.dispose();
		currentProgram = null;
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
			Program oldProg = currentProgram;
			Program newProg = ev.getActiveProgram();
			if (oldProg != null) {
				programClosed();
			}
			if (newProg != null) {
				programOpened(newProg);
			}
		}
	}

	private void programOpened(Program p) {
		p.addListener(this);
		currentProgram = p;
		provider.setProgram(p);
	}

	private void programClosed() {
		currentProgram.removeListener(this);
		currentProgram = null;
		provider.setProgram(null);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(ChangeManager.DOCR_IMAGE_BASE_CHANGED) ||
			ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			provider.setProgram(currentProgram);
		}

		int eventCnt = ev.numRecords();
		for (int i = 0; i < eventCnt; ++i) {
			DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);

			int eventType = doRecord.getEventType();
			if (!(doRecord instanceof ProgramChangeRecord)) {
				continue;
			}

			ProgramChangeRecord rec = (ProgramChangeRecord) doRecord;
			switch (eventType) {
				case ChangeManager.DOCR_RELOCATION_ADDED:
					Relocation relocation = (Relocation) rec.getNewValue();
					domainObjectWorker.schedule(new RelocationAddedJob(currentProgram, relocation));
					break;

				case ChangeManager.DOCR_RELOCATION_REMOVED:
					relocation = (Relocation) rec.getOldValue();
					domainObjectWorker.schedule(new RelocationRemovedJob(currentProgram, relocation));
					break;
			}
		}
	}

	private abstract class AbstractRelocationUpdateJob extends Job {

		protected Program program;

		AbstractRelocationUpdateJob(Program program) {
			this.program = program;
		}

		@Override
		public final void run(TaskMonitor taskMonitor) {
			if (program != currentProgram) {
				return;
			}
			doRun();
		}

		protected abstract void doRun();
	}

	private class RelocationAddedJob extends AbstractRelocationUpdateJob {

		private Relocation relocation;

		RelocationAddedJob(Program program, Relocation relocation) {
			super(program);
			this.relocation = relocation;
		}

		@Override
		protected void doRun() {
			provider.relocationAdded(relocation);
		}
	}

	private class RelocationRemovedJob extends AbstractRelocationUpdateJob {

		private Relocation relocation;

		RelocationRemovedJob(Program program, Relocation relocation) {
			super(program);
			this.relocation = relocation;
		}

		@Override
		protected void doRun() {
			provider.relocationRemoved(relocation);
		}
	}
}
