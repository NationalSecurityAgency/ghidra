/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.pcode.floatformat;

import java.util.HashMap;
import java.util.Map;

public class FloatFormatFactory {

	// TODO: This should really be a language specific interface
	// acting as a factory of float formats - Float Format should also be an interface.

	static final Map<Integer, FloatFormat> cache = new HashMap<Integer, FloatFormat>();

	/**
	 * Get float format
	 * @param size format storage size in bytes
	 * @return float format or null if size is not supported
	 */
	public static synchronized FloatFormat getFloatFormat(int size)
			throws UnsupportedFloatFormatException {

		FloatFormat format = cache.get(size);
		if (format == null) {
			format = new FloatFormat(size);
			cache.put(size, format);
		}
		return format;

	}

}
