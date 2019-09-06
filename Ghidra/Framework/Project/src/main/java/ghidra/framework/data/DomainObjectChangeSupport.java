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

class DomainObjectChangeSupport {

	private WeakSet<DomainObjectListener> listeners;
	private DomainObject src;
	private List<DomainObjectChangeRecord> changesQueue;
	private GhidraTimer timer;

	private Lock domainObjectLock;
	private Lock writeLock = new Lock("DOCS Change Records Queue Lock");

	private volatile boolean isDisposed;

	/**
	 * Constructs a new DomainObjectChangeSupport object.
	 * @param src The object to be put as the src for all events generated.
	 * @param timeInterval The time (in milliseconds) this object will wait before
	 * 		  flushing its event buffer.  If a new event comes in before the time expires,
	 * 		  the timer is reset.
	 * @param lock the lock used to verify that calls to {@link #flush()} are not performed 
	 *        while a lock is held; this is the lock to guard the DB
	 */
	DomainObjectChangeSupport(DomainObject src, int timeInterval, int bufsize, Lock lock) {

		this.src = src;
		this.domainObjectLock = Objects.requireNonNull(lock);
		changesQueue = new ArrayList<>(bufsize);

		listeners = WeakDataStructureFactory.createCopyOnWriteWeakSet();

		timer = GhidraTimerFactory.getGhidraTimer(timeInterval, timeInterval, () -> sendEventNow());
		timer.setInitialDelay(25);
		timer.setDelay(500);
		timer.setRepeats(true);
	}

	void addListener(DomainObjectListener listener) {

		// Capture the pending event to send to the existing listeners.  This prevents the new
		// listener from getting events registered before the listener was added.
		DomainObjectChangedEvent pendingEvent = convertEventQueueRecordsToEvent();
		List<DomainObjectListener> previousListeners = atomicAddListener(listener);

		/*
		 * Do later so that we do not get this deadlock:
		 * 	   Thread1 has Domain Lock -> wants AWT lock
		 *     Swing has AWT lock -> wants Domain lock
		 */
		SystemUtilities.runIfSwingOrPostSwingLater(
			() -> notifyEvent(previousListeners, pendingEvent));
	}

	void removeListener(DomainObjectListener listener) {
		listeners.remove(listener);
	}

	private void sendEventNow() {
		DomainObjectChangedEvent ev = convertEventQueueRecordsToEvent();
		notifyEvent(listeners, ev);
	}

	private DomainObjectChangedEvent convertEventQueueRecordsToEvent() {

		DomainObjectChangedEvent event = lockQueue(() -> {

			if (changesQueue.isEmpty()) {
				timer.stop();
				return null;
			}

			DomainObjectChangedEvent e = new DomainObjectChangedEvent(src, changesQueue);
			changesQueue = new ArrayList<>();
			return e;
		});

		return event;
	}

	// This version of notify takes in the listeners to notify so that we can send events to
	// some listeners, but not all of them (like flushing when adding new listeners)
	private void notifyEvent(Iterable<DomainObjectListener> listenersToNotify,
			DomainObjectChangedEvent ev) {

		if (ev == null) {
			return; // this implies there we no changes when the timer expired
		}

		if (isDisposed) {
			return;
		}

		for (DomainObjectListener dol : listenersToNotify) {
			try {
				dol.domainObjectChanged(ev);
			}
			catch (Exception exc) {
				Msg.showError(this, null, "Error", "Error in Domain Object listener", exc);
			}
		}
	}

	void flush() {
		Thread lockOwner = domainObjectLock.getOwner();
		if (lockOwner == Thread.currentThread()) {

			/*
			 * We have decided that flushing events with a lock can lead to deadlocks.  There
			 * should be no reason to flush events while holding a lock.   This is the 
			 * potential deadlock:			
			 * 	   Thread1 has Domain Lock -> wants AWT lock
			 *     Swing has AWT lock -> wants Domain lock
			 */

			throw new IllegalStateException("Cannot call flush() with locks!");
		}

		SystemUtilities.runSwingNow(() -> sendEventNow());
	}

	void fireEvent(DomainObjectChangeRecord docr) {

		if (isDisposed) {
			return;
		}

		lockQueue(() -> {
			changesQueue.add(docr);
			timer.start();
		});
	}

	void fatalErrorOccurred(final Throwable t) {

		List<DomainObjectListener> listenersCopy = new ArrayList<>(listeners.values());

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
					// I guess we don't care (probably because some other fatal error has 
					// already happened)
				}
			}
		};

		SystemUtilities.runSwingLater(errorTask);
	}

	void dispose() {

		lockQueue(() -> {
			isDisposed = true;
			timer.stop();
			changesQueue.clear();
		});

		listeners.clear();
	}

	private List<DomainObjectListener> atomicAddListener(DomainObjectListener l) {

		List<DomainObjectListener> previousLisetners = new ArrayList<>();
		for (DomainObjectListener listener : listeners) {
			previousLisetners.add(listener);
		}

		listeners.add(l);
		return previousLisetners;
	}

//==================================================================================================
// Lock Methods
//==================================================================================================

	private void lockQueue(Runnable r) {

		try {
			writeLock.acquire();
			r.run();
		}
		finally {
			writeLock.release();
		}
	}

	private <T> T lockQueue(Callable<T> c) {

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
}
