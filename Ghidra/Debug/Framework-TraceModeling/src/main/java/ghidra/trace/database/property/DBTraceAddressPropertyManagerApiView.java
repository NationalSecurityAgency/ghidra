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
package ghidra.trace.database.property;

import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import ghidra.trace.model.property.*;
import ghidra.util.exception.DuplicateNameException;

class DBTraceAddressPropertyManagerApiView implements TraceAddressPropertyManager {
	protected static final String API_PREFIX = "_API_";

	protected final DBTraceAddressPropertyManager internalView;

	public DBTraceAddressPropertyManagerApiView(DBTraceAddressPropertyManager internalView) {
		this.internalView = internalView;
	}

	@Override
	public <T> TracePropertyMap<T> createPropertyMap(String name, Class<T> valueClass)
			throws DuplicateNameException {
		return internalView.createPropertyMap(API_PREFIX + name, valueClass);
	}

	@Override
	public <T> TracePropertyMap<T> getPropertyMap(String name, Class<T> valueClass) {
		return internalView.getPropertyMap(API_PREFIX + name, valueClass);
	}

	@Override
	public <T> TracePropertyMap<T> getOrCreatePropertyMap(String name, Class<T> valueClass) {
		return internalView.getOrCreatePropertyMap(API_PREFIX + name, valueClass);
	}

	@Override
	public <T> TracePropertyGetter<T> getPropertyGetter(String name,
			Class<T> valueClass) {
		return internalView.getPropertyGetter(API_PREFIX + name, valueClass);
	}

	@Override
	public <T> TracePropertySetter<T> getOrCreatePropertySetter(String name,
			Class<T> valueClass) {
		return internalView.getOrCreatePropertySetter(API_PREFIX + name, valueClass);
	}

	@Override
	public TracePropertyMap<?> getPropertyMap(String name) {
		return internalView.getPropertyMap(API_PREFIX + name);
	}

	@Override
	public Map<String, TracePropertyMap<?>> getAllProperties() {
		return internalView.getAllProperties()
				.entrySet()
				.stream()
				.filter(e -> e.getKey().startsWith(API_PREFIX))
				.collect(Collectors.toMap(e -> e.getKey().substring(API_PREFIX.length()),
					Entry::getValue));
	}
}
