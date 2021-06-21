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
package ghidra.dbg.target;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.util.CollectionUtils.AbstractEmptyMap;
import ghidra.dbg.util.CollectionUtils.AbstractNMap;

/**
 * An object which can be invoked as a method
 * 
 * <p>
 * TODO: Should parameters and return type be something incorporated into Schemas?
 */
@DebuggerTargetObjectIface("Method")
public interface TargetMethod extends TargetObject {
	String PARAMETERS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "parameters";
	String RETURN_TYPE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "return_type";

	/**
	 * A description of a method parameter
	 * 
	 * <p>
	 * TODO: For convenience, these should be programmable via annotations.
	 * <P>
	 * TODO: Should this be incorporated into schemas?
	 * 
	 * @param <T> the type of the parameter
	 */
	class ParameterDescription<T> {
		/**
		 * Create a parameter
		 * 
		 * @param <T> the type of the parameter
		 * @param type the class representing the type of the parameter
		 * @param name the name of the parameter
		 * @param required true if this parameter must be provided
		 * @param defaultValue the default value of this parameter
		 * @param display the human-readable name of this parameter
		 * @param description the human-readable description of this parameter
		 * @return the new parameter description
		 */
		public static <T> ParameterDescription<T> create(Class<T> type, String name,
				boolean required, T defaultValue, String display, String description) {
			return new ParameterDescription<>(type, name, required, defaultValue, display,
				description, List.of());
		}

		/**
		 * Create a parameter having enumerated choices
		 * 
		 * @param <T> the type of the parameter
		 * @param type the class representing the type of the parameter
		 * @param name the name of the parameter
		 * @param choices the non-empty set of choices
		 * @param display the human-readable name of this parameter
		 * @param description the human-readable description of this parameter
		 * @return the new parameter description
		 */
		public static <T> ParameterDescription<T> choices(Class<T> type, String name,
				Collection<T> choices, String display, String description) {
			T defaultValue = choices.iterator().next();
			return new ParameterDescription<>(type, name, false, defaultValue, display, description,
				choices);
		}

		public final Class<T> type;
		public final String name;
		public final T defaultValue;
		public final boolean required;
		public final String display;
		public final String description;
		public final Set<T> choices;

		private ParameterDescription(Class<T> type, String name, boolean required, T defaultValue,
				String display, String description, Collection<T> choices) {
			this.type = type;
			this.name = name;
			this.defaultValue = defaultValue;
			this.required = required;
			this.display = display;
			this.description = description;
			this.choices = Set.copyOf(choices);
		}

		@Override
		public int hashCode() {
			return Objects.hash(type, name, defaultValue, required, display, description, choices);
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof ParameterDescription<?>)) {
				return false;
			}
			ParameterDescription<?> that = (ParameterDescription<?>) obj;
			if (this.type != that.type) {
				return false;
			}
			if (!Objects.equals(this.name, that.name)) {
				return false;
			}
			if (!Objects.equals(this.defaultValue, that.defaultValue)) {
				return false;
			}
			if (this.required != that.required) {
				return false;
			}
			if (!Objects.equals(this.display, that.display)) {
				return false;
			}
			if (!Objects.equals(this.description, that.description)) {
				return false;
			}
			if (!Objects.equals(this.choices, that.choices)) {
				return false;
			}
			return true;
		}

		/**
		 * Extract the argument for this parameter
		 * 
		 * <p>
		 * You must validate the arguments, using
		 * {@link TargetMethod#validateArguments(Map, Map, boolean)}, first.
		 * 
		 * @param arguments the validated arguments
		 * @return the parameter
		 */
		@SuppressWarnings("unchecked")
		public T get(Map<String, ?> arguments) {
			if (arguments.containsKey(name)) {
				return (T) arguments.get(name);
			}
			if (required) {
				throw new DebuggerIllegalArgumentException(
					"Missing required parameter '" + name + "'");
			}
			return defaultValue;
		}

		@Override
		public String toString() {
			return String.format(
				"<ParameterDescription " + "name=%s type=%s default=%s required=%s " +
					"display='%s' description='%s' choices=%s",
				name, type, defaultValue, required, display, description, choices);
		}
	}

	public interface TargetParameterMap extends Map<String, ParameterDescription<?>> {
		public static class EmptyTargetParameterMap extends
				AbstractEmptyMap<String, ParameterDescription<?>> implements TargetParameterMap {
			// Nothing
		}

		public static class ImmutableTargetParameterMap extends
				AbstractNMap<String, ParameterDescription<?>> implements TargetParameterMap {

			public ImmutableTargetParameterMap(Map<String, ParameterDescription<?>> map) {
				super(map);
			}
		}

		TargetParameterMap EMPTY = new EmptyTargetParameterMap();

		public static TargetParameterMap of() {
			return EMPTY;
		}

		public static TargetParameterMap copyOf(Map<String, ParameterDescription<?>> map) {
			return new ImmutableTargetParameterMap(map);
		}
	}

	/**
	 * Construct a map of parameter descriptions from a stream
	 * 
	 * @param params the descriptions
	 * @return a map of descriptions by name
	 */
	static TargetParameterMap makeParameters(Stream<ParameterDescription<?>> params) {
		return TargetParameterMap
				.copyOf(params.collect(Collectors.toMap(p -> p.name, p -> p, (a, b) -> {
					throw new IllegalArgumentException("duplicate parameters: " + a + " and " + b);
				}, LinkedHashMap::new)));
	}

	/**
	 * Construct a map of parameter descriptions from a collection
	 * 
	 * @param params the descriptions
	 * @return a map of descriptions by name
	 */
	static TargetParameterMap makeParameters(Collection<ParameterDescription<?>> params) {
		return makeParameters(params.stream());
	}

	/**
	 * Construct a map of parameter descriptions from an array
	 * 
	 * @param params the descriptions
	 * @return a map of descriptions by name
	 */
	static TargetParameterMap makeParameters(ParameterDescription<?>... params) {
		return makeParameters(Stream.of(params));
	}

	/**
	 * Validate the given arguments against the given parameters
	 * 
	 * @param parameters the parameter descriptions
	 * @param arguments the arguments
	 * @param permitExtras false to require every named argument has a named parameter
	 * @return the map of validated arguments
	 */
	static Map<String, ?> validateArguments(Map<String, ParameterDescription<?>> parameters,
			Map<String, ?> arguments, boolean permitExtras) {
		if (!permitExtras) {
			if (!parameters.keySet().containsAll(arguments.keySet())) {
				Set<String> extraneous = new TreeSet<>(arguments.keySet());
				extraneous.removeAll(parameters.keySet());
				throw new DebuggerIllegalArgumentException("Extraneous parameters: " + extraneous);
			}
		}
		Map<String, Object> valid = new LinkedHashMap<>();
		Map<String, String> typeErrors = null;
		Set<String> extraneous = null;
		for (Map.Entry<String, ?> ent : arguments.entrySet()) {
			String name = ent.getKey();
			Object val = ent.getValue();
			ParameterDescription<?> d = parameters.get(name);
			if (d == null && !permitExtras) {
				if (extraneous == null) {
					extraneous = new TreeSet<>();
				}
				extraneous.add(name);
			}
			else if (val != null && !d.type.isAssignableFrom(val.getClass())) {
				if (typeErrors == null) {
					typeErrors = new TreeMap<>();
				}
				typeErrors.put(name, "val '" + val + "' is not a " + d.type);
			}
			else {
				valid.put(name, val);
			}
		}
		if (typeErrors != null || extraneous != null) {
			StringBuilder sb = new StringBuilder();
			if (typeErrors != null) {
				sb.append("Type mismatches: ");
				sb.append(typeErrors);
			}
			if (extraneous != null) {
				sb.append("Extraneous parameters: ");
				sb.append(extraneous);
			}
			throw new DebuggerIllegalArgumentException(sb.toString());
		}
		return valid;
	}

	/**
	 * A convenience method used by {@link TargetLauncher} as a stopgap until "launch" becomes a
	 * {@link TargetMethod}.
	 * 
	 * @param obj the object having a "parameters" attribute.
	 * @return the parameter map
	 */
	static TargetParameterMap getParameters(TargetObject obj) {
		return obj.getTypedAttributeNowByName(PARAMETERS_ATTRIBUTE_NAME, TargetParameterMap.class,
			TargetParameterMap.of());
	}

	/**
	 * Get the parameter descriptions of this method
	 * 
	 * @return the name-description map of parameters
	 */
	@TargetAttributeType(
		name = PARAMETERS_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = true)
	default public TargetParameterMap getParameters() {
		return getParameters(this);
	}

	/**
	 * Get the return type of this method
	 * 
	 * <p>
	 * If the return type is {@link TargetObject} then it is most likely a link, but that is not
	 * necessarily the case. If the arguments alone determine the returned object, then the returned
	 * object can in fact be a canonical object whose path includes the invocation syntax.
	 * 
	 * @return the return type
	 */
	@TargetAttributeType(
		name = RETURN_TYPE_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = true)
	default public Class<?> getReturnType() {
		return getTypedAttributeNowByName(RETURN_TYPE_ATTRIBUTE_NAME, Class.class, Object.class);
	}

	// TODO: Allow extra parameters, i.e., varargs?

	/**
	 * Invoke the method with the given arguments
	 * 
	 * @param arguments the map of named arguments
	 * @return a future which completes with the return value
	 */
	CompletableFuture<Object> invoke(Map<String, ?> arguments);
}
