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
package generic.util;

import java.lang.reflect.*;
import java.util.LinkedHashMap;
import java.util.Map;

public class Beanify {
	public static Map<String, Object> beanify(Object beany) {
		LinkedHashMap<String, Object> result = new LinkedHashMap<String, Object>();
		Class<? extends Object> bclass = beany.getClass();
		Method[] declaredMethods = bclass.getDeclaredMethods();
		for (Method method : declaredMethods) {
			String name = fix(method.getName());
			if (name != null) {
				if (Modifier.isPublic(method.getModifiers()) &&
					!method.getReturnType().equals(Void.TYPE) &&
					method.getParameterTypes().length == 0) {
					try {
						method.setAccessible(true);
						Object thing = method.invoke(beany);
						result.put(name, thing);
					}
					catch (Exception e) {
						// squash this, report an error in the result
						result.put(name, e.toString());
					}
				}
			}
		}
		Field[] declaredFields = bclass.getDeclaredFields();
		for (Field field : declaredFields) {
			if (Modifier.isPublic(field.getModifiers())) {
				String name = field.getName();
				try {
					field.setAccessible(true);
					Object thing = field.get(beany);
					result.put(name, thing);
				}
				catch (Exception e) {
					// squash this, report an error in the result
					result.put(name, e.toString());
				}
			}
		}
		return result;
	}

	private static String fix(String name) {
		if (name.startsWith("get") && name.length() > 3) {
			return name.substring(3, 4).toLowerCase() + name.substring(4);
		}
		if (name.startsWith("is") && name.length() > 2) {
			return name.substring(2, 3).toLowerCase() + name.substring(3);
		}
		return null;
	}
}
