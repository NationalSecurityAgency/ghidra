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
package ghidra.trace.database.memory;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.junit.*;

import db.Transaction;
import ghidra.program.model.lang.LanguageID;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.util.LanguageTestWatcher;
import ghidra.util.database.DBCachedObjectStore;

public abstract class AbstractDBTraceMemoryManagerTest
		extends AbstractGhidraHeadlessIntegrationTest {
	protected ToyDBTraceBuilder b;
	protected DBTraceMemoryManager memory;

	@Rule
	public LanguageTestWatcher testLanguage =
		new LanguageTestWatcher(getLanguageID().getIdAsString());

	protected abstract LanguageID getLanguageID();

	@Before
	public void setUp() throws IOException {
		b = new ToyDBTraceBuilder("Testing", testLanguage.getLanguage());
		try (Transaction tx = b.startTransaction()) {
			b.trace.getTimeManager().createSnapshot("Initialize");
		}
		memory = b.trace.getMemoryManager();
	}

	@After
	public void tearDown() {
		b.close();
	}

	protected static void assertSnapState(long snap, TraceMemoryState state,
			Entry<TraceAddressSnapRange, TraceMemoryState> entry) {
		assertEquals(snap, entry.getKey().getY1().longValue());
		assertEquals(state, entry.getValue());
	}

	protected static Map<TraceAddressSnapRange, TraceMemoryState> collectAsMap(
			Iterable<Entry<TraceAddressSnapRange, TraceMemoryState>> it) {
		Map<TraceAddressSnapRange, TraceMemoryState> result = new HashMap<>();
		for (Entry<TraceAddressSnapRange, TraceMemoryState> entry : it) {
			assertNotNull(entry.getValue());
			TraceMemoryState old = result.put(entry.getKey(), entry.getValue());
			assertNull(old);
		}
		return result;
	}

	protected int getBlockRecordCount() {
		DBTraceMemorySpace space = memory.getForSpace(b.language.getDefaultSpace(), false);
		if (space == null) {
			return 0;
		}
		return space.blockStore.getRecordCount();
	}

	protected DBCachedObjectStore<DBTraceMemoryBufferEntry> getBufferStore() {
		DBTraceMemorySpace space = memory.getForSpace(b.language.getDefaultSpace(), false);
		if (space == null) {
			return null;
		}
		return space.bufferStore;
	}

	protected int getBufferRecordCount() {
		DBCachedObjectStore<DBTraceMemoryBufferEntry> bufferStore = getBufferStore();
		if (bufferStore == null) {
			return 0;
		}
		return bufferStore.getRecordCount();
	}

}
