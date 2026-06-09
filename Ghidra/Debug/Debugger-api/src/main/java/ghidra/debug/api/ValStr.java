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
package ghidra.debug.api;

import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.stream.Collectors;

public record ValStr<T>(T val, String str) {

	public interface Decoder<T> {
		default ValStr<T> decodeValStr(String string) {
			return new ValStr<>(decode(string), string);
		}

		T decode(String string);
	}

	public static ValStr<String> str(String value) {
		return new ValStr<>(value, value);
	}

	public static <T> ValStr<T> from(T value) {
		return new ValStr<>(value, value == null ? "" : value.toString());
	}

	@SuppressWarnings("unchecked")
	public static <T> ValStr<T> cast(Class<T> cls, ValStr<?> value) {
		if (cls.isInstance(value.val)) {
			return (ValStr<T>) value;
		}
		return new ValStr<>(cls.cast(value.val), value.str);
	}

	public static Map<String, ValStr<?>> fromPlainMap(Map<String, ?> map) {
		return map.entrySet()
				.stream()
				.collect(Collectors.toMap(Entry::getKey, e -> ValStr.from(e.getValue())));
	}

	public static Map<String, ? super Object> toPlainMap(Map<String, ValStr<?>> map) {
		return map.entrySet()
				.stream()
				.collect(Collectors.toMap(Entry::getKey, e -> e.getValue().val()));
	}

	public static String normStr(ValStr<?> val) {
		if (val == null) {
			return "";
		}
		return val.normStr();
	}

	public String normStr() {
		if (val == null) {
			return "";
		}
		return Objects.toString(val);
	}
}
