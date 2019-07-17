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
package ghidra.framework.client;

import java.io.InterruptedIOException;

import ghidra.framework.remote.RepositoryChangeEvent;
import ghidra.framework.store.FileSystemListener;

class RepositoryChangeDispatcher implements Runnable {

	private FileSystemListener changeListener;
	private RepositoryAdapter repAdapter;

	private volatile Thread thread;

	RepositoryChangeDispatcher(RepositoryAdapter repAdapter) {
		this.repAdapter = repAdapter;
	}

	@Override
	public void run() {
		try {
			while (thread != null) {
				processEvents(repAdapter.getEvents());
			}
		}
		catch (InterruptedIOException e) {
			// ignore
		}
	}

	public void setFileChangeListener(FileSystemListener changeListener) {
		this.changeListener = changeListener;
	}

	public synchronized void stop() {
		if (thread != null) {
			thread.interrupt(); // may have no affect on pending RMI call
			thread = null;
		}
	}

	public synchronized void start() {
		stop();
		thread = new Thread(this, "RepChangeDispatcher-" + repAdapter.getName());
		thread.setDaemon(true);
		thread.start();
	}

	private void processEvents(RepositoryChangeEvent[] events) {
		if (changeListener == null) {
			return;
		}
		for (int i = 0; thread != null && i < events.length; i++) {
			RepositoryChangeEvent event = events[i];
			switch (event.type) {
				case RepositoryChangeEvent.REP_OPEN_HANDLE_COUNT:
					repAdapter.processOpenHandleCountUpdateEvent(event);
					break;
				case RepositoryChangeEvent.REP_FOLDER_CREATED:
					changeListener.folderCreated(event.parentPath, event.name);
					break;
				case RepositoryChangeEvent.REP_FOLDER_DELETED:
					changeListener.folderDeleted(event.parentPath, event.name);
					break;
				case RepositoryChangeEvent.REP_FOLDER_MOVED:
					changeListener.folderMoved(event.parentPath, event.name, event.newParentPath);
					break;
				case RepositoryChangeEvent.REP_FOLDER_RENAMED:
					changeListener.folderRenamed(event.parentPath, event.name, event.newName);
					break;
				case RepositoryChangeEvent.REP_ITEM_CHANGED:
					changeListener.itemChanged(event.parentPath, event.name);
					break;
				case RepositoryChangeEvent.REP_ITEM_CREATED:
					changeListener.itemCreated(event.parentPath, event.name);
					break;
				case RepositoryChangeEvent.REP_ITEM_DELETED:
					changeListener.itemDeleted(event.parentPath, event.name);
					break;
				case RepositoryChangeEvent.REP_ITEM_MOVED:
					changeListener.itemMoved(event.parentPath, event.name, event.newParentPath,
						event.newName);
					break;
				case RepositoryChangeEvent.REP_ITEM_RENAMED:
					changeListener.itemRenamed(event.parentPath, event.name, event.newName);
					break;
			}
		}

	}
}
