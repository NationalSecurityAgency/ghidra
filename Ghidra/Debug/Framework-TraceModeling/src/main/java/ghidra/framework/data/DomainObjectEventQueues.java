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

import java.util.Map;
import java.util.NoSuchElementException;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalNotification;

import ghidra.framework.model.*;
import ghidra.util.Lock;

public class DomainObjectEventQueues {
	protected final DomainObject source;
	protected final Lock lock;
	protected final DomainObjectChangeSupport eventQueue;
	protected final Map<EventQueueID, DomainObjectChangeSupport> privateEventQueues = CacheBuilder
		.newBuilder().removalListener(this::privateQueueRemoved).weakKeys().build().asMap();

	protected volatile boolean eventsEnabled = true;

	public DomainObjectEventQueues(DomainObject source, int timeInterval, int bufsize, Lock lock) {
		this.source = source;
		this.lock = lock;
		eventQueue = new DomainObjectChangeSupport(source, timeInterval, bufsize, lock);
	}

	private void privateQueueRemoved(
			RemovalNotification<EventQueueID, DomainObjectChangeSupport> rn) {
		rn.getValue().dispose();
	}

	public void flushEvents() {
		eventQueue.flush();
		for (DomainObjectChangeSupport privateQueue : privateEventQueues.values()) {
			privateQueue.flush();
		}
	}

	public synchronized void addListener(DomainObjectListener l) {
		eventQueue.addListener(l);
	}

	public synchronized void removeListener(DomainObjectListener l) {
		eventQueue.removeListener(l);
	}

	public EventQueueID createPrivateEventQueue(DomainObjectListener listener, int maxDelay) {
		EventQueueID id = new EventQueueID();
		DomainObjectChangeSupport privateQueue =
			new DomainObjectChangeSupport(source, maxDelay, 1000, lock);
		privateQueue.addListener(listener);
		privateEventQueues.put(id, privateQueue);
		return id;
	}

	public boolean removePrivateEventQueue(EventQueueID id) {
		return privateEventQueues.remove(id) != null;
		// NOTE: Removal callback will dispose()
	}

	public void flushPrivateEventQueue(EventQueueID id) {
		DomainObjectChangeSupport privateQueue = privateEventQueues.get(id);
		if (privateQueue == null) {
			throw new NoSuchElementException("Private queue no longer exists");
		}
		privateQueue.flush();
	}

	public void fireEvent(DomainObjectChangeRecord ev) {
		if (eventsEnabled) {
			eventQueue.fireEvent(ev);
			for (DomainObjectChangeSupport privateQueue : privateEventQueues.values()) {
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
			for (DomainObjectChangeSupport privateQueue : privateEventQueues.values()) {
				privateQueue.fireEvent(restored);
			}
		}
	}

	public boolean isSendingEvents() {
		return eventsEnabled;
	}
}
