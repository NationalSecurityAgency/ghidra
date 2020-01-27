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
package ghidra.framework.store;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * <code>FileSystemListenerList</code> maintains a list of FileSystemListener's.
 * This class, acting as a FileSystemListener, simply relays each callback to
 * all FileSystemListener's within its list.  Employs either a synchronous 
 * and asynchronous notification mechanism.
 */
public class FileSystemListenerList implements FileSystemListener {

	private List<FileSystemListener> listenerList = new CopyOnWriteArrayList<>();

	private List<FileSystemEvent> events =
		Collections.synchronizedList(new LinkedList<FileSystemEvent>());

	private boolean enableAsynchronousDispatching;
	private boolean isEventProcessingThreadWaiting;
	private boolean alive = true;
	private Object lock = new Object();
	private Thread thread;

	/**
	 * Construct FileSystemListenerList
	 * @param enableAsynchronousDispatching if true a separate dispatch thread will be used
	 * to notify listeners.  If false, blocking notification will be performed.
	 */
	public FileSystemListenerList(boolean enableAsynchronousDispatching) {
		this.enableAsynchronousDispatching = enableAsynchronousDispatching;
	}

	public void dispose() {
		alive = false;
		synchronized (lock) {
			lock.notify();
		}
	}

	/**
	 * Add a listener to this list.
	 * @param listener
	 */
	public synchronized void add(FileSystemListener listener) {
		listenerList.add(listener);
		if (thread == null && enableAsynchronousDispatching) {
			thread = new FileSystemEventProcessingThread();
			thread.setName("File System Listener");
			thread.start();
		}
	}

	/**
	 * Remove a listener from this list.
	 * @param listener
	 */
	public void remove(FileSystemListener listener) {
		listenerList.remove(listener);
	}

	/**
	 * Remove all listeners from this list.
	 */
	public void clear() {
		listenerList.clear();
	}

	/**
	 * Forwards itemMoved callback to all listeners within this list.
	 * @see ghidra.framework.store.FileSystemListener#itemMoved(String, String, String, String)
	 */
	@Override
	public void itemMoved(String parentPath, String name, String newParentPath, String newName) {
		if (enableAsynchronousDispatching) {
			add(new ItemMovedEvent(parentPath, name, newParentPath, newName));
		}
		else {
			for (FileSystemListener l : listenerList) {
				l.itemMoved(parentPath, name, newParentPath, newName);
			}
		}
	}

	/**
	 * Forwards itemRenamed callback to all listeners within this list.
	 * @see ghidra.framework.store.FileSystemListener#itemRenamed(String, String, String)
	 */
	@Override
	public void itemRenamed(String parentPath, String itemName, String newName) {
		if (enableAsynchronousDispatching) {
			add(new ItemRenamedEvent(parentPath, itemName, newName));
		}
		else {
			for (FileSystemListener l : listenerList) {
				l.itemRenamed(parentPath, itemName, newName);
			}
		}
	}

	/**
	 * Forwards itemDeleted callback to all listeners within this list.
	 * @see ghidra.framework.store.FileSystemListener#itemDeleted(String, String)
	 */
	@Override
	public void itemDeleted(String parentPath, String itemName) {
		if (enableAsynchronousDispatching) {
			add(new ItemDeletedEvent(parentPath, itemName));
		}
		else {
			for (FileSystemListener l : listenerList) {
				l.itemDeleted(parentPath, itemName);
			}
		}
	}

	/**
	 * Forwards folderRenamed callback to all listeners within this list.
	 * @see ghidra.framework.store.FileSystemListener#folderRenamed(String, String, String)
	 */
	@Override
	public void folderRenamed(String parentPath, String folderName, String newFolderName) {
		if (enableAsynchronousDispatching) {
			add(new FolderRenamedEvent(parentPath, folderName, newFolderName));
		}
		else {
			for (FileSystemListener l : listenerList) {
				l.folderRenamed(parentPath, folderName, newFolderName);
			}
		}
	}

	/**
	 * Forwards folderMoved callback to all listeners within this list.
	 * @see ghidra.framework.store.FileSystemListener#folderMoved(String, String, String)
	 */
	@Override
	public void folderMoved(String parentPath, String folderName, String newParentPath) {
		if (enableAsynchronousDispatching) {
			add(new FolderMovedEvent(parentPath, folderName, newParentPath));
		}
		else {
			for (FileSystemListener l : listenerList) {
				l.folderMoved(parentPath, folderName, newParentPath);
			}
		}
	}

	/**
	 * Forwards folderDeleted callback to all listeners within this list.
	 * @see ghidra.framework.store.FileSystemListener#folderDeleted(String, String)
	 */
	@Override
	public void folderDeleted(String parentPath, String folderName) {
		if (enableAsynchronousDispatching) {
			add(new FolderDeletedEvent(parentPath, folderName));
		}
		else {
			for (FileSystemListener l : listenerList) {
				l.folderDeleted(parentPath, folderName);
			}
		}
	}

	/**
	 * Forwards itemCreated callback to all listeners within this list.
	 * @see ghidra.framework.store.FileSystemListener#itemCreated(String, String)
	 */
	@Override
	public void itemCreated(String parentPath, String itemName) {
		if (enableAsynchronousDispatching) {
			add(new ItemCreatedEvent(parentPath, itemName));
		}
		else {
			for (FileSystemListener l : listenerList) {
				l.itemCreated(parentPath, itemName);
			}
		}
	}

	/**
	 * Forwards folderCreated callback to all listeners within this list.
	 * @see ghidra.framework.store.FileSystemListener#folderCreated(String, String)
	 */
	@Override
	public void folderCreated(String parentPath, String folderName) {
		if (enableAsynchronousDispatching) {
			add(new FolderCreatedEvent(parentPath, folderName));
		}
		else {
			for (FileSystemListener l : listenerList) {
				l.folderCreated(parentPath, folderName);
			}
		}
	}

	/**
	 * Forwards itemChanged callback to all listeners within this list.
	 * @see ghidra.framework.store.FileSystemListener#itemChanged(String, String)
	 */
	@Override
	public void itemChanged(String parentPath, String itemName) {
		if (enableAsynchronousDispatching) {
			add(new ItemChangedEvent(parentPath, itemName));
		}
		else {
			for (FileSystemListener l : listenerList) {
				l.itemChanged(parentPath, itemName);
			}
		}
	}

	/**
	 * Forwards syncronize callback to all listeners within this list.
	 * @see ghidra.framework.store.FileSystemListener#syncronize()
	 */
	@Override
	public void syncronize() {
		if (enableAsynchronousDispatching) {
			add(new SynchronizeEvent());
		}
	}

	private void add(FileSystemEvent ev) {
		if (!listenerList.isEmpty()) {
			events.add(ev);
			synchronized (lock) {
				lock.notify();
			}
		}
	}

	/**
	 * Returns true if this class is processing events <b>or</b> needs to process events that are
	 * in its event queue. 
	 * 
	 * @return true if this class is processing events <b>or</b> needs to process events that are
	 * in its event queue. 
	 */
	public boolean isProcessingEvents() {
		synchronized (this) {
			if (thread == null) {
				return false; // non-threaded; does not 'process' events, done synchronously
			}
		}

		synchronized (lock) { // lock so nobody adds new events
			return !isEventProcessingThreadWaiting || (events.size() > 0);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class FileSystemEventProcessingThread extends Thread {

		FileSystemEventProcessingThread() {
			super("File System Event Processor");
			setDaemon(true);
		}

		@Override
		public void run() {
			while (alive) {
				while (!events.isEmpty()) {
					FileSystemEvent event;
					synchronized (lock) {
						event = events.remove(0);
					}
					synchronized (FileSystemListenerList.this) {
						for (FileSystemListener l : listenerList) {
							event.dispatch(l);
						}
					}
				}
				doWait();
			}
		}

		private void doWait() {
			try {
				synchronized (lock) {
					if (alive && events.isEmpty()) {
						isEventProcessingThreadWaiting = true;
						lock.wait();
					}
				}
			}
			catch (InterruptedException e) {
			}
			finally {
				isEventProcessingThreadWaiting = false;
			}
		}
	}

	private static abstract class FileSystemEvent {
		String parentPath;
		String name;
		String newParentPath;
		String newName;

		FileSystemEvent(String parentPath, String name, String newParentPath, String newName) {
			this.parentPath = parentPath;
			this.name = name;
			this.newParentPath = newParentPath;
			this.newName = newName;
		}

		abstract void dispatch(FileSystemListener listener);
	}

	private static class ItemMovedEvent extends FileSystemEvent {
		ItemMovedEvent(String parentPath, String name, String newParentPath, String newName) {
			super(parentPath, name, newParentPath, newName);
		}

		@Override
		void dispatch(FileSystemListener listener) {
			listener.itemMoved(parentPath, name, newParentPath, newName);
		}
	}

	private static class ItemRenamedEvent extends FileSystemEvent {
		ItemRenamedEvent(String parentPath, String name, String newName) {
			super(parentPath, name, null, newName);
		}

		@Override
		void dispatch(FileSystemListener listener) {
			listener.itemRenamed(parentPath, name, newName);
		}
	}

	private static class ItemDeletedEvent extends FileSystemEvent {
		ItemDeletedEvent(String parentPath, String name) {
			super(parentPath, name, null, null);
		}

		@Override
		void dispatch(FileSystemListener listener) {
			listener.itemDeleted(parentPath, name);
		}
	}

	private static class FolderMovedEvent extends FileSystemEvent {
		FolderMovedEvent(String parentPath, String name, String newParentPath) {
			super(parentPath, name, newParentPath, null);
		}

		@Override
		void dispatch(FileSystemListener listener) {
			listener.folderMoved(parentPath, name, newParentPath);
		}
	}

	private static class FolderRenamedEvent extends FileSystemEvent {
		FolderRenamedEvent(String parentPath, String name, String newName) {
			super(parentPath, name, null, newName);
		}

		@Override
		void dispatch(FileSystemListener listener) {
			listener.folderRenamed(parentPath, name, newName);
		}
	}

	private static class FolderDeletedEvent extends FileSystemEvent {
		FolderDeletedEvent(String parentPath, String name) {
			super(parentPath, name, null, null);
		}

		@Override
		void dispatch(FileSystemListener listener) {
			listener.folderDeleted(parentPath, name);
		}
	}

	private static class ItemCreatedEvent extends FileSystemEvent {
		ItemCreatedEvent(String parentPath, String name) {
			super(parentPath, name, null, null);
		}

		@Override
		void dispatch(FileSystemListener listener) {
			listener.itemCreated(parentPath, name);
		}
	}

	private static class FolderCreatedEvent extends FileSystemEvent {
		FolderCreatedEvent(String parentPath, String name) {
			super(parentPath, name, null, null);
		}

		@Override
		void dispatch(FileSystemListener listener) {
			listener.folderCreated(parentPath, name);
		}
	}

	private static class ItemChangedEvent extends FileSystemEvent {
		ItemChangedEvent(String parentPath, String name) {
			super(parentPath, name, null, null);
		}

		@Override
		void dispatch(FileSystemListener listener) {
			listener.itemChanged(parentPath, name);
		}
	}

	private static class SynchronizeEvent extends FileSystemEvent {
		SynchronizeEvent() {
			super(null, null, null, null);
		}

		@Override
		void dispatch(FileSystemListener listener) {
			listener.syncronize();
		}
	}
}
