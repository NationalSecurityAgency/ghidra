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

import ghidra.util.Msg;

public enum ValueUtils {
	;
	public static final boolean INCLUDE_STACK = false;

	public static void reportErr(Object val, Class<?> cls, Object logObj, String attributeName) {
		String message =
			"expected " + cls.getSimpleName() + " for " + attributeName + ", but got " + val;
		if (INCLUDE_STACK) {
			Msg.error(logObj, message, new Throwable());
		}
		else {
			Msg.error(logObj, message);
		}
	}

	public static <T> T expectType(Object val, Class<T> cls, Object logObj, String attributeName,
			T fallback, boolean required) {
		if (val == null || !cls.isAssignableFrom(val.getClass())) {
			if (val != null || required) {
				reportErr(val, cls, logObj, attributeName);
			}
			return fallback;
		}
		return cls.cast(val);
	}
}
