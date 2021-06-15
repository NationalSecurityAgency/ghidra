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
package ghidra.dbg.util;

import java.util.LinkedHashMap;
import java.util.Map;

import utility.function.ExceptionalFunction;

/**
 * A utility for parsing strings into objects
 *
 * This utility is suited to controlling a command-line application via its input and output
 * streams. The application is expected to display command results, statuses, events, etc., by
 * printing one line per item. This utility provides a straightforward mechanism for selecting a
 * line parser by examining the first characters.
 *
 * The prefix-to-constructor map is populated by calling {@link #put(Object, ExceptionalFunction)}
 * and other methods inherited from {@link Map}. The function is typically a constructor reference.
 * When parsing a line, the prefixes are examined in the order added. If a matching prefix is found,
 * it is removed from the line and the tail is passed to the corresponding constructor. If the tail
 * starts with a comma, it is also removed. The constructed instance is then returned to the caller.
 *
 * @param <T> the base class for the parser types
 * @param <E> the base class for checked exceptions that must be handled by callers
 */
public class PrefixMap<T, E extends Exception>
		extends LinkedHashMap<String, ExceptionalFunction<? super String, ? extends T, E>> {

	/**
	 * Construct a representation of the given line by selecting and invoking a constructor
	 * 
	 * @param line the line to parse
	 * @return the object of the mapped type as parsed by its constructor or {@code null} if the
	 *         line does not match a prefix
	 * @throws E if the constructor throws an exception
	 */
	public T construct(String line) throws E {
		for (java.util.Map.Entry<String, ExceptionalFunction<? super String, ? extends T, E>> ent : entrySet()) {
			String prefix = ent.getKey();
			if (line.startsWith(prefix)) {
				String tail = line.substring(prefix.length());
				if (tail.startsWith(",")) {
					tail = tail.substring(1);
				}
				ExceptionalFunction<? super String, ? extends T, E> cons = ent.getValue();
				return cons.apply(tail);
			}
		}
		return null;
	}
}
