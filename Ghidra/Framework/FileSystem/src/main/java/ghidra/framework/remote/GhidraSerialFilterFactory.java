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
package ghidra.framework.remote;

import java.io.ObjectInputFilter;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BinaryOperator;

/**
 * {@link GhidraSerialFilterFactory} provides the serial filter factory which imposes
 * {@link GhidraObjectInputFilter} as a global serial input filter.
 * <p>
 * NOTE: With the use of Gradle test JVM instances it may be neccessary for those instances
 * to specify this class as the serial filter factory and rely on lazy initialization of the
 * {@link GhidraObjectInputFilter global serial filter}.
 * <pre>
 * 		-Djdk.serialFilterFactory=ghidra.framework.remote.GhidraSerialFilterFactory
 * </pre>
 */
public class GhidraSerialFilterFactory implements BinaryOperator<ObjectInputFilter> {

	private static final AtomicReference<GhidraSerialFilterFactory> filterFactoryRef =
		new AtomicReference<>();

	private final GhidraObjectInputFilter globalFilter;

	/**
	 * Constructor.  Caller is reposponsible for installation.
	 * See {@link ObjectInputFilter.Config#setSerialFilterFactory}.
	 */
	public GhidraSerialFilterFactory() {
		if (!filterFactoryRef.compareAndSet(null, this)) {
			throw new IllegalStateException(
				"Serial filter factory has previously been instantiated");
		}
		globalFilter = new GhidraObjectInputFilter();
	}

	GhidraObjectInputFilter getSerialFilter() {
		return globalFilter;
	}

	@Override
	public ObjectInputFilter apply(ObjectInputFilter current, ObjectInputFilter requested) {
		// Merge any existing/requested filter with our strict global filter.
		// Our filter is always applied.
		if (current == null && requested == null) {
			return globalFilter;
		}
		if (current == null) {
			return ObjectInputFilter.merge(requested, globalFilter);
		}
		if (requested == null) {
			return ObjectInputFilter.merge(current, globalFilter);
		}
		return ObjectInputFilter.merge(ObjectInputFilter.merge(current, requested),
			globalFilter);
	}

	/**
	 * Get, and install if neccessary, the serial filter factory instance. If a new factory is
	 * installed it will have an uninitialized {@link GhidraObjectInputFilter} instance.
	 * <p>
	 * See {@link java.io.ObjectInputFilter.Config#setSerialFilterFactory(java.util.function.BinaryOperator)}.
	 * 
	 * @return serial filter factory singleton instance
	 * @throws IllegalStateException if the serial input factory has already been established and
	 * cannot be updated.
	 */
	static synchronized GhidraSerialFilterFactory getOrInstallInstance()
			throws IllegalStateException {
		GhidraSerialFilterFactory factory = filterFactoryRef.get();
		if (factory != null) {
			return factory;
		}
		GhidraSerialFilterFactory newFactory = new GhidraSerialFilterFactory();
		ObjectInputFilter.Config.setSerialFilterFactory(newFactory);
		return newFactory;
	}
}
