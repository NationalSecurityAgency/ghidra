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
package ghidra.framework.data;

import java.util.*;
import java.util.concurrent.Callable;

import generic.timer.GhidraTimer;
import generic.timer.GhidraTimerFactory;
import ghidra.framework.model.*;
import ghidra.util.*;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

/**
 * A class to queue and send {@link DomainObjectChangeRecord} events.
 * <p>
 * For simplicity, this class requires all mutations to internal data structures to be locked using
 * the internal write lock.  Clients are not required to use any synchronization when using this
 * class.
 * <p>
 * Internally, events are queued and will be fired on a timer.
 */
class DomainObjectChangeSupport {

	private WeakSet<DomainObjectListener> listeners =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();
	private List<EventNotification> notificationQueue = new ArrayList<>();
	private List<DomainObjectChangeRecord> recordsQueue = new ArrayList<>();

	private GhidraTimer timer;

	private DomainObject src;
	private Lock domainObjectLock;
	private Lock writeLock = new Lock("DOCS Change Records Queue Lock");

	private volatile boolean isDisposed;

	/**
	 * Constructs a new DomainObjectChangeSupport object.
	 *
	 * @param src The object to be put as the src for all events generated.
	 * @param timeInterval The time (in milliseconds) this object will wait before flushing its
	 * event buffer. If a new event comes in before the time expires, the timer is reset.
	 * @param lock the lock used to verify that calls to {@link #flush()} are not performed while a
	 * lock is held; this is the lock to guard the DB
	 */
	DomainObjectChangeSupport(DomainObject src, int timeInterval, Lock lock) {

		this.src = Objects.requireNonNull(src);
		this.domainObjectLock = Objects.requireNonNull(lock);
		this.timer =
			GhidraTimerFactory.getGhidraTimer(timeInterval, timeInterval, this::sendEventNow);
		timer.setInitialDelay(25);
		timer.setDelay(500);
		timer.setRepeats(true);
	}

	// Note: must be called inside of withLock()
	private DomainObjectChangedEvent createEventFromQueuedRecords() {

		if (recordsQueue.isEmpty()) {
			timer.stop();
			return null;
		}

		DomainObjectChangedEvent e = new DomainObjectChangedEvent(src, recordsQueue);
		recordsQueue = new ArrayList<>();
		return e;
	}

	void addListener(DomainObjectListener listener) {

		if (isDisposed) {
			return;
		}

		withLock(() -> {

			// Capture the pending event to send to the existing listeners.  This prevents the new
			// listener from getting events registered before the listener was added.  Also, create
			// a new set of listeners so that any events already posted to the Swing thread do not
			// see the newly added listener.
			Collection<DomainObjectListener> previousListeners = listeners.values();
			listeners.add(listener);

			DomainObjectChangedEvent pendingEvent = createEventFromQueuedRecords();
			if (pendingEvent != null) {
				notificationQueue.add(new EventNotification(pendingEvent, previousListeners));
				timer.start();
			}
		});
	}

	void removeListener(DomainObjectListener listener) {
		if (isDisposed) {
			return;
		}

		//
		// Note: any events posted to the Swing thread may still notify this listener after it has
		//       been removed, since a copy of the set will be used.
		//
		withLock(() -> listeners.remove(listener));
	}

	void flush() {
		Thread lockOwner = domainObjectLock.getOwner();
		if (lockOwner == Thread.currentThread()) {

			//
			// We have decided that flushing events with a lock can lead to deadlocks.  There
			// should be no reason to flush events while holding a lock.   This is the potential
			// deadlock:
			// 		Thread1 has Domain Lock -> wants AWT lock
			// 		Swing has AWT lock -> wants Domain lock
			//
			throw new IllegalStateException("Cannot call flush() with locks!");
		}

		sendEventNow();
	}

	private void sendEventNow() {
		List<EventNotification> notifications = withLock(() -> {

			DomainObjectChangedEvent e = createEventFromQueuedRecords();
			if (e != null) {
				notificationQueue.add(new EventNotification(e, listeners.values()));
			}

			if (notificationQueue.isEmpty()) {
				return Collections.emptyList();
			}

			List<EventNotification> existingNotifications = new ArrayList<>(notificationQueue);
			notificationQueue.clear();
			return existingNotifications;
		});

		if (notifications.isEmpty()) {
			return;
		}

		Swing.runNow(() -> doSendEventsNow(notifications));
	}

	// Note: must be called on the Swing thread
	private void doSendEventsNow(List<EventNotification> notifications) {
		for (EventNotification notification : notifications) {
			notification.doNotify();
		}
	}

	void fireEvent(DomainObjectChangeRecord docr) {

		if (isDisposed) {
			return;
		}

		withLock(() -> {
			recordsQueue.add(docr);
			timer.start();
		});
	}

	void fatalErrorOccurred(Throwable t) {

		if (isDisposed) {
			return;
		}

		List<DomainObjectListener> listenersCopy =
			withLock(() -> new ArrayList<>(listeners.values()));

		dispose();

		Runnable errorTask = () -> {
			List<DomainObjectChangeRecord> records =
				Arrays.asList(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_ERROR, null, t));
			DomainObjectChangedEvent ev = new DomainObjectChangedEvent(src, records);
			for (DomainObjectListener l : listenersCopy) {
				try {
					l.domainObjectChanged(ev);
				}
				catch (Throwable t2) {
					// We don't care (probably because some other fatal error has already happened)
				}
			}
		};

		Swing.runLater(errorTask);
	}

	void dispose() {

		if (isDisposed) {
			return;
		}

		withLock(() -> {
			isDisposed = true;
			timer.stop();
			recordsQueue.clear();
			notificationQueue.clear();
			listeners.clear();
		});
	}

//=================================================================================================
// Lock Methods
//=================================================================================================

	// Note: all clients of lockQueue() must not call external APIs that could use locking
	private void withLock(Runnable r) {

		try {
			writeLock.acquire();
			r.run();
		}
		finally {
			writeLock.release();
		}
	}

	// Note: all clients of lockQueue() must not call external APIs that could use locking
	private <T> T withLock(Callable<T> c) {

		try {
			writeLock.acquire();
			T result;
			try {
				result = c.call();
				return result;
			}
			catch (Exception e) {
				// sholudn't happen
				Msg.error(this, "Exception while updating change records", e);
				return null;
			}
		}
		finally {
			writeLock.release();
		}
	}

//=================================================================================================
// Inner Classes
//=================================================================================================

	/**
	 * This class allows us to bind the given event with the given listeners.  This is used to
	 * send events to the correct listeners as listeners are added.  In other words, new listeners
	 * will not receive pre-existing buffered events.   Also, using this class allows us to ensure
	 * events are processed linearly by processing each of these notification objects linearly
	 * from a single queue.
	 *
	 * Note: this class shall perform no synchronization; that shall be handled by the client
	 */
	private class EventNotification {

		private DomainObjectChangedEvent event;
		private Collection<DomainObjectListener> receivers;

		EventNotification(DomainObjectChangedEvent event,
				Collection<DomainObjectListener> recievers) {
			this.event = event;
			this.receivers = recievers;
		}

		// Note: must be called on the Swing thread; must be called outside of lockQueue()
		void doNotify() {

			if (isDisposed) {
				return;
			}

			if (event == null) {
				return; // this implies there were no changes when the timer expired
			}

			for (DomainObjectListener dol : receivers) {
				try {
					dol.domainObjectChanged(event);
				}
				catch (Exception exc) {
					Msg.showError(this, null, "Error", "Error in Domain Object listener", exc);
				}
			}
		}
	}
}
