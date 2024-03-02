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
package ghidra.trace.database.target;

import java.util.Objects;

import ghidra.trace.model.Lifespan;

public class DBTraceObjectValueBehind implements TraceObjectValueStorage {
	private final DBTraceObjectManager manager;

	private final DBTraceObject parent;
	private final String entryKey;
	private Lifespan lifespan;
	private final Object value;

	private boolean deleted = false;

	private final DBTraceObjectValue wrapper;

	public DBTraceObjectValueBehind(DBTraceObjectManager manager, DBTraceObject parent,
			String entryKey, Lifespan lifespan, Object value) {
		this.manager = manager;

		this.parent = Objects.requireNonNull(parent, "Root cannot be delayed");
		this.entryKey = entryKey;
		this.lifespan = lifespan;
		this.value = value;

		this.wrapper = new DBTraceObjectValue(manager, this);
	}

	@Override
	public String toString() {
		return "<%s parent=%s entryKey=%s lifespan=%s value=%s>".formatted(
			getClass().getSimpleName(), parent, entryKey, lifespan, value);
	}

	@Override
	public String getEntryKey() {
		return entryKey;
	}

	@Override
	public Object getValue() {
		return value;
	}

	@Override
	public Lifespan getLifespan() {
		return lifespan;
	}

	@Override
	public boolean isDeleted() {
		return deleted;
	}

	@Override
	public DBTraceObjectManager getManager() {
		return manager;
	}

	@Override
	public DBTraceObject getChildOrNull() {
		if (value instanceof DBTraceObject child) {
			return child;
		}
		return null;
	}

	@Override
	public void doSetLifespan(Lifespan lifespan) {
		var values = manager.valueWbCache.doRemoveNoCleanup(this);
		this.lifespan = lifespan;
		manager.valueWbCache.doAddDirect(values, this);
	}

	@Override
	public void doDelete() {
		deleted = true;
		manager.doDeleteCachedValue(this);
	}

	@Override
	public DBTraceObject getParent() {
		return parent;
	}

	@Override
	public DBTraceObjectValue getWrapper() {
		return wrapper;
	}
}
