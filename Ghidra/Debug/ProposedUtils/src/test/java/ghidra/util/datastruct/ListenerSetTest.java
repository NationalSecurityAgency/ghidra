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
package ghidra.util.datastruct;

import static org.junit.Assert.assertEquals;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import ghidra.util.datastruct.ListenerSet;

public class ListenerSetTest {
	public interface DummyListener {
		void event(String e);
	}

	@Test
	public void testBehavesLikeSetAndMultiplexes() {
		ListenerSet<DummyListener> listeners = new ListenerSet<>(DummyListener.class);
		AtomicInteger ai1 = new AtomicInteger();
		DummyListener d1 = e -> {
			ai1.getAndIncrement();
		};
		AtomicInteger ai2 = new AtomicInteger();
		DummyListener d2 = e -> {
			ai2.getAndIncrement();
		};
		listeners.add(d1);
		listeners.add(d2);

		listeners.fire.event("EventA");
		assertEquals(1, ai1.get());
		assertEquals(1, ai2.get());

		listeners.add(d1); // This had better not double fire

		listeners.fire.event("EventB");
		assertEquals(2, ai1.get());
		assertEquals(2, ai2.get());
	}

	@Test
	public void testContinuesOnError() {
		ListenerSet<DummyListener> listeners = new ListenerSet<>(DummyListener.class);

		AtomicReference<String> ar1 = new AtomicReference<>();
		DummyListener d1 = e -> {
			ar1.set(e);
			throw new RuntimeException("It had better continue (1)");
		};
		listeners.add(d1);

		AtomicReference<String> ar2 = new AtomicReference<>();
		DummyListener d2 = e -> {
			ar2.set(e);
			throw new RuntimeException("It had better continue (2)");
		};
		listeners.add(d2);

		listeners.fire.event("Should see on both");
		assertEquals("Should see on both", ar1.get());
		assertEquals("Should see on both", ar2.get());
	}

	@Test
	public void testWeaklyReferencesListeners() {
		ListenerSet<DummyListener> listeners = new ListenerSet<>(DummyListener.class);

		AtomicReference<String> ar1 = new AtomicReference<>();
		DummyListener d1 = e -> {
			ar1.set(e);
			throw new RuntimeException("It had better continue (1)");
		};
		listeners.add(d1);

		listeners.fire.event("EventA");
		assertEquals("EventA", ar1.get());

		d1 = null; // Trash the only strong reference
		System.gc();

		listeners.fire.event("EventB");
		assertEquals("EventA", ar1.get());
	}
}
