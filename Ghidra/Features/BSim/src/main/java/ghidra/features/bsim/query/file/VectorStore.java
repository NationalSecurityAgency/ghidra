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
package ghidra.features.bsim.query.file;

import java.sql.SQLException;
import java.util.Iterator;
import java.util.Map;

import org.apache.commons.collections4.iterators.EmptyIterator;

import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.util.Msg;

public class VectorStore implements Iterable<VectorStoreEntry> {

	private BSimServerInfo serverInfo;
	private Map<Long, VectorStoreEntry> vectors = null;

	public VectorStore(BSimServerInfo serverInfo) {
		if (serverInfo.getDBType() != DBType.file) {
			throw new IllegalArgumentException("Unsupported DBType");
		}
		this.serverInfo = serverInfo;
	}

	private void init() {
		if (vectors == null) {
			try {
				loadVectors();
			}
			catch (SQLException e) {
				// TODO: do we need different interface to properly convey error?
				Msg.error(this, "Failed to load vectors for " + serverInfo + ": " + e.getMessage());
			}
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	public synchronized Iterator<VectorStoreEntry> iterator() {
		init();
		if (vectors == null) {
			return EmptyIterator.INSTANCE;
		}
		return vectors.values().iterator();
	}

	public synchronized VectorStoreEntry getVectorById(long id) {
		init();
		if (vectors == null) {
			return null;
		}
		return vectors.get(id);
	}

	private void loadVectors() throws SQLException {
		// NOTE: assume file DB (see constructor above)
		try (H2FileFunctionDatabase fnDb = new H2FileFunctionDatabase(serverInfo)) {
			if (!fnDb.initialize()) {
				throw new SQLException(fnDb.getLastError().message);
			}
			vectors = fnDb.readVectorMap();
		}
	}

	public synchronized void invalidate() {
		vectors = null;
	}

	public synchronized void update(VectorStoreEntry entry) {
		if (vectors != null) {
			vectors.put(entry.id(), entry);
		}
	}

	public synchronized void update(long id, int count) {
		if (vectors == null) {
			return;
		}
		VectorStoreEntry entry = vectors.get(id);
		if (entry == null) {
			invalidate();
		}
		else {
			vectors.put(id, new VectorStoreEntry(id, entry.vec(), count, entry.selfSig()));
		}
	}

	public synchronized void delete(long id) {
		if (vectors != null) {
			vectors.remove(id);
		}
	}

}
