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

import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import ghidra.util.datastruct.ListenerMap;

public class ListenerMapTest {
	public interface DummyListener {
		void event(String e);
	}

	@Test
	public void testBehavesLikeMap() {
		ListenerMap<String, DummyListener, DummyListener> listeners =
			new ListenerMap<>(DummyListener.class);
		DummyListener d1 = e -> {
		};
		DummyListener d2 = e -> {
		};
		listeners.put("Key1", d1);
		listeners.put("Key2", d2);
		assertEquals(d1, listeners.get("Key1"));
		assertEquals(d2, listeners.get("Key2"));
		listeners.put("Key1", d2);
		assertEquals(d2, listeners.get("Key1"));
	}

	@Test
	public void testMultiplexes() {
		ListenerMap<String, DummyListener, DummyListener> listeners =
			new ListenerMap<>(DummyListener.class);
		AtomicReference<String> ar1 = new AtomicReference<>();
		listeners.put("Key1", ar1::set);
		listeners.fire.event("EventA");
		assertEquals("EventA", ar1.get());
		AtomicReference<String> ar2 = new AtomicReference<>();
		listeners.put("Key2", ar2::set);
		listeners.fire.event("EventB");
		assertEquals("EventB", ar1.get());
		assertEquals("EventB", ar2.get());
		AtomicReference<String> ar3 = new AtomicReference<>();
		listeners.put("Key1", ar3::set); // Overwrite Key1
		listeners.fire.event("EventC");
		assertEquals("EventB", ar1.get());
		assertEquals("EventC", ar2.get());
		assertEquals("EventC", ar3.get());
	}

	@Test
	public void testContinuesOnError() {
		ListenerMap<String, DummyListener, DummyListener> listeners =
			new ListenerMap<>(DummyListener.class);

		AtomicReference<String> ar1 = new AtomicReference<>();
		DummyListener d1 = e -> {
			ar1.set(e);
			throw new RuntimeException("It had better continue (1)");
		};
		listeners.put("Key1", d1);

		AtomicReference<String> ar2 = new AtomicReference<>();
		DummyListener d2 = e -> {
			ar2.set(e);
			throw new RuntimeException("It had better continue (2)");
		};
		listeners.put("Key2", d2);

		listeners.fire.event("Should see on both");
		assertEquals("Should see on both", ar1.get());
		assertEquals("Should see on both", ar2.get());
	}

	@Test
	public void testWeaklyReferencesListeners() {
		ListenerMap<String, DummyListener, DummyListener> listeners =
			new ListenerMap<>(DummyListener.class);

		AtomicReference<String> ar1 = new AtomicReference<>();
		DummyListener d1 = e -> {
			ar1.set(e);
			throw new RuntimeException("It had better continue (1)");
		};
		listeners.put("Key1", d1);

		listeners.fire.event("EventA");
		assertEquals("EventA", ar1.get());

		d1 = null; // Trash the only strong reference
		System.gc();

		listeners.fire.event("EventB");
		assertEquals("EventA", ar1.get());
	}
}
