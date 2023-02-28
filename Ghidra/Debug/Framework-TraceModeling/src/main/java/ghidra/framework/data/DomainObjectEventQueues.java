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

import java.lang.ref.Cleaner;
import java.util.*;

import ghidra.framework.model.*;
import ghidra.util.Lock;

public class DomainObjectEventQueues {
	protected static class PrivateQueue {
		private static final Cleaner CLEANER = Cleaner.create();

		static class State implements Runnable {
			final DomainObjectChangeSupport docs;

			public State(DomainObjectChangeSupport docs) {
				this.docs = docs;
			}

			@Override
			public void run() {
				docs.dispose();
			}
		}

		private final State state;
		private final Cleaner.Cleanable cleanable;

		public PrivateQueue(DomainObjectChangeSupport docs) {
			this.state = new State(docs);
			this.cleanable = CLEANER.register(this, state);
		}

		public void flush() {
			state.docs.flush();
		}

		public void fireEvent(DomainObjectChangeRecord ev) {
			state.docs.fireEvent(ev);
		}
	}

	protected final DomainObject source;
	protected final Lock lock;
	protected final DomainObjectChangeSupport eventQueue;
	protected final Map<EventQueueID, PrivateQueue> privateEventQueues = new WeakHashMap<>();

	protected volatile boolean eventsEnabled = true;

	public DomainObjectEventQueues(DomainObject source, int timeInterval, Lock lock) {
		this.source = source;
		this.lock = lock;
		eventQueue = new DomainObjectChangeSupport(source, timeInterval, lock);
	}

	public void flushEvents() {
		eventQueue.flush();
		for (PrivateQueue privateQueue : privateEventQueues.values()) {
			privateQueue.flush();
		}
	}

	public void addListener(DomainObjectListener l) {
		eventQueue.addListener(l);
	}

	public void removeListener(DomainObjectListener l) {
		eventQueue.removeListener(l);
	}

	public EventQueueID createPrivateEventQueue(DomainObjectListener listener, int maxDelay) {
		EventQueueID id = new EventQueueID();
		DomainObjectChangeSupport docs = new DomainObjectChangeSupport(source, maxDelay, lock);
		docs.addListener(listener);
		privateEventQueues.put(id, new PrivateQueue(docs));
		return id;
	}

	public boolean removePrivateEventQueue(EventQueueID id) {
		PrivateQueue privateQueue = privateEventQueues.remove(id);
		if (privateQueue == null) {
			return false;
		}
		privateQueue.cleanable.clean();
		return true;
	}

	public void flushPrivateEventQueue(EventQueueID id) {
		PrivateQueue privateQueue = privateEventQueues.get(id);
		if (privateQueue == null) {
			throw new NoSuchElementException("Private queue no longer exists");
		}
		privateQueue.flush();
	}

	public void fireEvent(DomainObjectChangeRecord ev) {
		if (eventsEnabled) {
			eventQueue.fireEvent(ev);
			for (PrivateQueue privateQueue : privateEventQueues.values()) {
				privateQueue.fireEvent(ev);
			}
		}
	}

	public void setEventsEnabled(boolean eventsEnabled) {
		if (this.eventsEnabled == eventsEnabled) {
			return;
		}
		this.eventsEnabled = eventsEnabled;
		if (eventsEnabled) {
			DomainObjectChangeRecord restored =
				new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED);
			eventQueue.fireEvent(restored);
			for (PrivateQueue privateQueue : privateEventQueues.values()) {
				privateQueue.fireEvent(restored);
			}
		}
	}

	public boolean isSendingEvents() {
		return eventsEnabled;
	}
}
