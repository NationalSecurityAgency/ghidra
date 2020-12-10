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

import java.util.Collection;

import ghidra.dbg.attributes.TargetObjectRefList;
import ghidra.dbg.target.TargetBreakpointContainer.TargetBreakpointKindSet;
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
			T fallback) {
		if (val == null || !cls.isAssignableFrom(val.getClass())) {
			reportErr(val, cls, logObj, attributeName);
			return fallback;
		}
		return cls.cast(val);
	}

	public static boolean expectBoolean(Object val, Object logObj, String attributeName,
			boolean fallback) {
		Boolean exp = expectType(val, Boolean.class, logObj, attributeName, null);
		if (exp == null) {
			return fallback;
		}
		return exp;
	}

	@SuppressWarnings("unchecked")
	public static <T extends Collection<E>, E> Class<T> colOf(Class<? super T> colType,
			Class<E> elemType) {
		return (Class<T>) colType;
	}

	public static <T extends Collection<E>, E> T expectCollectionOf(Object val, Class<T> colType,
			Class<E> elemType, Object logObj,
			String attributeName, T fallback) {
		if (!colType.isAssignableFrom(val.getClass())) {
			reportErr(val, colType, logObj, attributeName);
			return fallback;
		}
		T col = colType.cast(val);
		for (E e : col) {
			if (!elemType.isAssignableFrom(e.getClass())) {
				reportErr(e, elemType, logObj, "element of " + attributeName);
				return fallback;
			}
		}
		return col;
	}

	public static TargetBreakpointKindSet expectBreakKindSet(Object val, Object logObj,
			String attributeName, TargetBreakpointKindSet fallback) {
		return expectType(val, TargetBreakpointKindSet.class, logObj, attributeName, fallback);
	}

	public static TargetObjectRefList<?> expectTargetObjectRefList(Object val,
			Object logObj, String attributeName, TargetObjectRefList<?> fallback) {
		return expectType(val, TargetObjectRefList.class, logObj, attributeName, fallback);
	}
}
