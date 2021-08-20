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

import java.util.List;
import java.util.concurrent.*;

/**
 * <code>FileSystemListenerList</code> maintains a list of FileSystemListener's.
 * This class, acting as a FileSystemListener, simply relays each callback to
 * all FileSystemListener's within its list.  Employs either a synchronous 
 * and asynchronous notification mechanism.
 */
public class FileSystemEventManager implements FileSystemListener {

	private List<FileSystemListener> listeners = new CopyOnWriteArrayList<>();
	private BlockingQueue<FileSystemEvent> eventQueue = new LinkedBlockingQueue<>();

	private volatile boolean disposed = false;
	private Thread thread;

	/**
	 * Constructor
	 * @param enableAsynchronousDispatching if true a separate dispatch thread will be used
	 * to notify listeners.  If false, blocking notification will be performed.
	 */
	public FileSystemEventManager(boolean enableAsynchronousDispatching) {

		if (enableAsynchronousDispatching) {
			thread = new FileSystemEventProcessingThread();
			thread.start();
		}
	}

	public void dispose() {
		disposed = true;
		if (thread != null) {
			thread.interrupt();
		}
	}

	/**
	 * Add a listener to this list.
	 * @param listener the listener
	 */
	public void add(FileSystemListener listener) {
		listeners.add(listener);
	}

	/**
	 * Remove a listener from this list.
	 * @param listener the listener
	 */
	public void remove(FileSystemListener listener) {
		listeners.remove(listener);
	}

	@Override
	public void itemMoved(String parentPath, String name, String newParentPath, String newName) {
		handleEvent(new ItemMovedEvent(parentPath, name, newParentPath, newName));
	}

	@Override
	public void itemRenamed(String parentPath, String itemName, String newName) {
		handleEvent(new ItemRenamedEvent(parentPath, itemName, newName));
	}

	@Override
	public void itemDeleted(String parentPath, String itemName) {
		handleEvent(new ItemDeletedEvent(parentPath, itemName));
	}

	@Override
	public void folderRenamed(String parentPath, String folderName, String newFolderName) {
		handleEvent(new FolderRenamedEvent(parentPath, folderName, newFolderName));
	}

	@Override
	public void folderMoved(String parentPath, String folderName, String newParentPath) {
		handleEvent(new FolderMovedEvent(parentPath, folderName, newParentPath));
	}

	@Override
	public void folderDeleted(String parentPath, String folderName) {
		handleEvent(new FolderDeletedEvent(parentPath, folderName));
	}

	@Override
	public void itemCreated(String parentPath, String itemName) {
		handleEvent(new ItemCreatedEvent(parentPath, itemName));
	}

	@Override
	public void folderCreated(String parentPath, String folderName) {
		handleEvent(new FolderCreatedEvent(parentPath, folderName));
	}

	@Override
	public void itemChanged(String parentPath, String itemName) {
		handleEvent(new ItemChangedEvent(parentPath, itemName));
	}

	@Override
	public void syncronize() {
		// Note: synchronize calls will only work when using a threaded event queue
		if (isAsynchronous()) {
			add(new SynchronizeEvent());
		}
	}

	private boolean isAsynchronous() {
		return thread != null;
	}

	private void add(FileSystemEvent ev) {
		if (!listeners.isEmpty()) {
			eventQueue.add(ev);
		}
	}

	private void handleEvent(FileSystemEvent e) {
		if (disposed) {
			return;
		}

		if (isAsynchronous()) {
			add(e);
		}
		else {
			e.process(listeners);
		}
	}

	/**
	 * Blocks until all current events have been processed.
	 * <p>
	 * Note: clients should only use this method when {@link #isAsynchronous()} returns true, since
	 * this class cannot track when non-threaded events have finished broadcasting to listeners.
	 * In a synchronous use case, any test that needs to know when client events have been processed
	 * must use some other mechanism to know when event processing is finished.  
	 * 
	 * @param timeout the maximum time to wait
	 * @param unit the time unit of the {@code time} argument
	 * @return true if the events were processed in the given timeout
	 * @throws InterruptedException if this waiting thread is interrupted
	 */
	public boolean flushEvents(long timeout, TimeUnit unit) throws InterruptedException {
		if (!isAsynchronous()) {
			return true; // each thread processes its own event
		}

		MarkerEvent event = new MarkerEvent();
		eventQueue.add(event);
		return event.waitForEvent(timeout, unit);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class FileSystemEventProcessingThread extends Thread {

		FileSystemEventProcessingThread() {
			super("File System Listener");
			setDaemon(true);
		}

		@Override
		public void run() {
			while (!disposed) {

				FileSystemEvent event;
				try {
					event = eventQueue.take();
					event.process(listeners);
				}
				catch (InterruptedException e) {
					// interrupt has been cleared; if other threads rely on this interrupted state,
					// then mark the thread as interrupted again by calling: 
					// Thread.currentThread().interrupt();
					// For now, this code relies on the 'alive' flag to know when to terminate
				}
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

		void process(List<FileSystemListener> listeners) {
			for (FileSystemListener l : listeners) {
				dispatch(l);
			}
		}

		abstract void dispatch(FileSystemListener listener);

		@Override
		public String toString() {
			return getClass().getSimpleName();
		}
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

	// an event used by the flush method to mark when current events have been processed
	private static class MarkerEvent extends FileSystemEvent {

		private CountDownLatch latch = new CountDownLatch(1);

		MarkerEvent() {
			super(null, null, null, null);
		}

		@Override
		void dispatch(FileSystemListener listener) {
			// we don't actually process the event
		}

		@Override
		void process(List<FileSystemListener> listeners) {
			latch.countDown();
		}

		boolean waitForEvent(long timeout, TimeUnit unit) throws InterruptedException {
			return latch.await(timeout, unit);
		}
	}

}
