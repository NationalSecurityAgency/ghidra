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
package utilities.util;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

/**
 * Some utilities for reflection using annotations
 */
public enum AnnotationUtilities {
	;

	/**
	 * Collect from among the given class, its superclasses, and its interfaces all methods
	 * annotated with the given annotation type.
	 * 
	 * @param annotCls the annotation type
	 * @param cls the class whose methods to examine
	 * @return the set of all methods having the given annotation type
	 */
	public static Set<Method> collectAnnotatedMethods(Class<? extends Annotation> annotCls,
			Class<?> cls) {
		Set<Method> defs = new HashSet<>();
		collectAnnotatedMethods(annotCls, cls, defs, new HashSet<>());
		return defs;
	}

	private static void collectAnnotatedMethods(Class<? extends Annotation> annotCls, Class<?> cls,
			Set<Method> defs,
			Set<Class<?>> visited) {
		if (!visited.add(cls)) {
			return;
		}
		Class<?> superCls = cls.getSuperclass();
		if (superCls != null) {
			collectAnnotatedMethods(annotCls, superCls, defs, visited);
		}
		for (Class<?> superIf : cls.getInterfaces()) {
			collectAnnotatedMethods(annotCls, superIf, defs, visited);
		}
		collectAnnotatedMethodsForClass(annotCls, cls, defs);
	}

	private static void collectAnnotatedMethodsForClass(Class<? extends Annotation> annotCls,
			Class<?> cls, Set<Method> defs) {
		for (Method method : cls.getDeclaredMethods()) {
			Annotation annot = method.getAnnotation(annotCls);
			if (annot == null) {
				continue;
			}
			defs.add(method);
		}
	}
}
