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
package ghidra.electron.headless;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

import com.google.gson.JsonElement;

class EventBroker {
	private static final int MAX_HISTORY = 2048;

	private final AtomicLong nextSequence = new AtomicLong(0);
	private final List<ServerEvent> history = new ArrayList<>();
	private final Set<EventSubscription> subscriptions = ConcurrentHashMap.newKeySet();

	synchronized EventSubscription subscribe(long since) {
		long oldest = history.isEmpty() ? nextSequence.get() + 1 : history.get(0).sequence;
		if (since > 0 && !history.isEmpty() && since < oldest - 1) {
			throw new ApiException(410, "EVENT_CURSOR_EXPIRED",
				"The requested event cursor is no longer available.",
				Map.of("requestedSince", since, "oldestAvailable", oldest));
		}

		EventSubscription subscription = new EventSubscription(this);
		for (ServerEvent event : history) {
			if (event.sequence > since) {
				subscription.offer(event);
			}
		}
		subscriptions.add(subscription);
		return subscription;
	}

	synchronized ServerEvent publish(String eventType, Object payload) {
		JsonElement jsonPayload = JsonSupport.GSON.toJsonTree(payload);
		ServerEvent event = new ServerEvent(nextSequence.incrementAndGet(), eventType, jsonPayload);
		history.add(event);
		while (history.size() > MAX_HISTORY) {
			history.remove(0);
		}
		for (EventSubscription subscription : subscriptions) {
			subscription.offer(event);
		}
		return event;
	}

	void unsubscribe(EventSubscription subscription) {
		subscriptions.remove(subscription);
	}

	static class EventSubscription implements AutoCloseable {
		private final EventBroker broker;
		private final BlockingQueue<ServerEvent> queue = new LinkedBlockingQueue<>();
		private volatile boolean closed;

		EventSubscription(EventBroker broker) {
			this.broker = broker;
		}

		void offer(ServerEvent event) {
			if (!closed) {
				queue.offer(event);
			}
		}

		ServerEvent poll(long timeout, TimeUnit unit) throws InterruptedException {
			return queue.poll(timeout, unit);
		}

		@Override
		public void close() {
			closed = true;
			broker.unsubscribe(this);
		}
	}
}
