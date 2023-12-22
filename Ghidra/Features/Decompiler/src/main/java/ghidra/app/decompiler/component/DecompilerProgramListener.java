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
package ghidra.app.decompiler.component;

import java.util.Iterator;

import ghidra.framework.model.*;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.util.task.SwingUpdateManager;

/**
 * Listener of {@link Program} events for decompiler panels. Program events are buffered using 
 * a {@link SwingUpdateManager} before triggering a new decompile process.
 */
public class DecompilerProgramListener implements DomainObjectListener {

	private DecompilerController controller;
	private SwingUpdateManager updater;

	/**
	 * Construct a listener with a callback to be called when a decompile should occur. Program
	 * events are buffered using SwingUpdateManager before the callback is called.
	 * @param controller the DecompilerController
	 * @param callback the callback for when the decompile should be refreshed.
	 */
	public DecompilerProgramListener(DecompilerController controller, Runnable callback) {
		this(controller, new SwingUpdateManager(500, 5000, callback));
	}

	/**
	 * Construct a listener with a SwingUpdateManger that should be kicked for every
	 * program change.
	 * @param controller the DecompilerController
	 * @param updater A SwingUpdateManger to be kicked as program events are received which will
	 * eventually trigger a decompile refresh.
	 */
	public DecompilerProgramListener(DecompilerController controller, SwingUpdateManager updater) {
		this.controller = controller;
		this.updater = updater;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		// Check for events that signal that a decompiler process' data is stale
		// and if so force a new process to be spawned
		if (ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_REMOVED) ||
			ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			controller.resetDecompiler();
		}
		else if (ev.containsEvent(DomainObject.DO_PROPERTY_CHANGED)) {
			Iterator<DomainObjectChangeRecord> iter = ev.iterator();
			while (iter.hasNext()) {
				DomainObjectChangeRecord record = iter.next();
				if (record.getEventType() == DomainObject.DO_PROPERTY_CHANGED) {
					if (record.getOldValue() instanceof String) {
						String value = (String) record.getOldValue();
						if (value.startsWith(SpecExtension.SPEC_EXTENSION)) {
							controller.resetDecompiler();
							break;
						}
					}
				}
			}
		}

		updater.update();
	}

	public void dispose() {
		updater.dispose();
	}
}
