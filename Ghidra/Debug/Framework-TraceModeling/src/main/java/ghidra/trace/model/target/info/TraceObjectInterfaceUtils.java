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
package ghidra.trace.model.target.info;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.event.ChangeEvent;

import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInterfaceFactory.Constructor;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.util.LockHold;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.DuplicateNameException;

public enum TraceObjectInterfaceUtils {
	;

	private static class Private {
		private Map<Class<?>, Constructor<?>> mapByClass = null;
		private Map<String, Constructor<?>> mapByName = null;

		public Private() {
			ClassSearcher.addChangeListener(this::classesChanged);
		}

		private synchronized void classesChanged(ChangeEvent evt) {
			mapByClass = null;
		}

		private void checkRefresh() {
			if (mapByClass == null) {
				List<TraceObjectInterfaceFactory> instances =
					ClassSearcher.getInstances(TraceObjectInterfaceFactory.class);
				if (instances.isEmpty()) {
					Msg.warn(this, "ClassSearcher not active, yet. Falling back to built-ins");
					instances = List.of(new BuiltinTraceObjectInterfaceFactory());
				}
				mapByClass = instances
						.stream()
						.flatMap(f -> f.getInterfaceConstructors().stream())
						.collect(Collectors.toUnmodifiableMap(
							Constructor::iface,
							Function.identity()));
				mapByName = mapByClass.values()
						.stream()
						.collect(Collectors.toUnmodifiableMap(
							c -> getSchemaName(c.iface()),
							Function.identity()));
			}
		}

		private synchronized Map<Class<?>, Constructor<?>> getMapByClass() {
			checkRefresh();
			return mapByClass;
		}

		private synchronized Map<String, Constructor<?>> getMapByName() {
			checkRefresh();
			return mapByName;
		}
	}

	private static final Private PRIVATE = new Private();

	public static Map<Class<?>, Constructor<?>> getAllConstructors() {
		return PRIVATE.getMapByClass();
	}

	public static Stream<Constructor<?>> streamConstructors(TraceObjectSchema schema) {
		return schema.getInterfaces().stream().map(PRIVATE.getMapByClass()::get);
	}

	public static boolean isTraceObject(Class<?> cls) {
		return cls == TraceObject.class || TraceObjectInterface.class.isAssignableFrom(cls);
	}

	public static Map<String, Constructor<?>> getConstructorsByName() {
		return PRIVATE.getMapByName();
	}

	public static TraceObjectInfo requireAnnotation(Class<? extends TraceObjectInterface> traceIf) {
		TraceObjectInfo annot = traceIf.getAnnotation(TraceObjectInfo.class);
		if (annot == null) {
			throw new IllegalArgumentException(
				traceIf + " is missing @" + TraceObjectInfo.class + " annotation");
		}
		return annot;
	}

	public static String getSchemaName(Class<? extends TraceObjectInterface> traceIf) {
		return requireAnnotation(traceIf).schemaName();
	}

	public static String getShortName(Class<? extends TraceObjectInterface> traceIf) {
		return requireAnnotation(traceIf).shortName();
	}

	public static Collection<String> getFixedKeys(
			Class<? extends TraceObjectInterface> traceIf) {
		return List.of(requireAnnotation(traceIf).fixedKeys());
	}

	public static void setLifespan(Class<? extends TraceObjectInterface> traceIf,
			TraceObject object, Lifespan lifespan) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			for (TraceObjectValue val : object.getParents(Lifespan.ALL)) {
				if (val.isCanonical() && !val.isDeleted()) {
					val.setLifespan(lifespan, ConflictResolution.DENY);
				}
			}
		}
		catch (DuplicateKeyException e) {
			throw new DuplicateNameException(
				"Duplicate " + getShortName(traceIf) + ": " + e.getMessage());
		}
		object.insert(lifespan, ConflictResolution.TRUNCATE);
		long lower = lifespan.lmin();
		for (String key : getFixedKeys(traceIf)) {
			TraceObjectValue val = object.getValue(lower, key);
			if (val != null) {
				val.setLifespan(lifespan, ConflictResolution.TRUNCATE);
			}
		}
	}

	public static <T> T getValue(TraceObject object, long snap, String key, Class<T> cls, T def) {
		TraceObjectValue value = object.getValue(snap, key);
		if (value == null) {
			return def;
		}
		return cls.cast(value.getValue());
	}
}
