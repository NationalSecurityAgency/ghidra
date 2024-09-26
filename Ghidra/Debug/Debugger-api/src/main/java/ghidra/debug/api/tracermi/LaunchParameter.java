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
package ghidra.debug.api.tracermi;

import java.util.*;

import ghidra.debug.api.ValStr;

public record LaunchParameter<T>(Class<T> type, String name, String display, String description,
		boolean required, List<T> choices, ValStr<T> defaultValue, ValStr.Decoder<T> decoder) {

	public static <T> LaunchParameter<T> create(Class<T> type, String name, String display,
			String description, boolean required, ValStr<T> defaultValue,
			ValStr.Decoder<T> decoder) {
		return new LaunchParameter<>(type, name, display, description, required, List.of(),
			defaultValue, decoder);
	}

	public static <T> LaunchParameter<T> choices(Class<T> type, String name, String display,
			String description, Collection<T> choices, ValStr<T> defaultValue) {
		return new LaunchParameter<>(type, name, display, description, false,
			List.copyOf(new LinkedHashSet<>(choices)), defaultValue, str -> {
				for (T t : choices) {
					if (t.toString().equals(str)) {
						return t;
					}
				}
				return null;
			});
	}

	public static Map<String, LaunchParameter<?>> mapOf(Collection<LaunchParameter<?>> parameters) {
		Map<String, LaunchParameter<?>> result = new LinkedHashMap<>();
		for (LaunchParameter<?> param : parameters) {
			LaunchParameter<?> exists = result.put(param.name(), param);
			if (exists != null) {
				throw new IllegalArgumentException(
					"Duplicate names in parameter map: first=%s, second=%s".formatted(exists,
						param));
			}
		}
		return Collections.unmodifiableMap(result);
	}

	public static Map<String, ValStr<?>> validateArguments(
			Map<String, LaunchParameter<?>> parameters, Map<String, ValStr<?>> arguments) {
		if (!parameters.keySet().containsAll(arguments.keySet())) {
			Set<String> extraneous = new TreeSet<>(arguments.keySet());
			extraneous.removeAll(parameters.keySet());
			throw new IllegalArgumentException("Extraneous parameters: " + extraneous);
		}

		Map<String, String> typeErrors = null;
		for (Map.Entry<String, ValStr<?>> ent : arguments.entrySet()) {
			String name = ent.getKey();
			ValStr<?> val = ent.getValue();
			LaunchParameter<?> param = parameters.get(name);
			if (val.val() != null && !param.type.isAssignableFrom(val.val().getClass())) {
				if (typeErrors == null) {
					typeErrors = new LinkedHashMap<>();
				}
				typeErrors.put(name, "val '%s' is not a %s".formatted(val.val(), param.type()));
			}
		}
		if (typeErrors != null) {
			throw new IllegalArgumentException("Type errors: " + typeErrors);
		}
		return arguments;
	}

	public static Map<String, LaunchParameter<?>> mapOf(LaunchParameter<?>... parameters) {
		return mapOf(Arrays.asList(parameters));
	}

	public ValStr<T> decode(String string) {
		return decoder.decodeValStr(string);
	}

	public ValStr<T> get(Map<String, ValStr<?>> arguments) {
		if (arguments.containsKey(name)) {
			return ValStr.cast(type, arguments.get(name));
		}
		if (required) {
			throw new IllegalArgumentException(
				"Missing required parameter '%s' (%s)".formatted(display, name));
		}
		return defaultValue;
	}

	public void set(Map<String, ValStr<?>> arguments, ValStr<T> value) {
		arguments.put(name, value);
	}
}
