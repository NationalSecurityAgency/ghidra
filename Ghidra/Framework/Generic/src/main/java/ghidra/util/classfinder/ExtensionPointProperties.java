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
package ghidra.util.classfinder;

import java.lang.annotation.*;

/**
 * {@link ExtensionPoint} properties
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface ExtensionPointProperties {

	/**
	 * Default {@link ExtensionPoint} priority.  Higher values represent higher priorities.
	 */
	final static int DEFAULT_PRIORITY = 1;

	/**
	 * Default behavior for an {@link ExtensionPoint} being discoverable
	 */
	final static boolean DEFAULT_EXCLUDE = false;

	/**
	 * {@link ExtensionPoint} priority.  Higher values represent higher priorities.
	 * 
	 * @return the {@link ExtensionPoint} priority.  
	 */
	int priority() default DEFAULT_PRIORITY;

	/**
	 * Enable to exclude an {@link ExtensionPoint} from being discovered
	 * 
	 * @return true to exclude an {@link ExtensionPoint} from being discovered
	 */
	boolean exclude() default DEFAULT_EXCLUDE;

	/**
	 * Utility methods for working with {@link ExtensionPointProperties}
	 */
	public static class Util {

		/**
		 * Gets whether or not the {@link ExtensionPoint} will be excluded from being discovered
		 * 
		 * @param c the class check
		 * @return true if the class is an {@link ExtensionPoint} and should be excluded from being
		 *   discovered 
		 */
		public static boolean isExcluded(Class<?> c) {
			ExtensionPointProperties properties = c.getAnnotation(ExtensionPointProperties.class);
			return properties != null ? properties.exclude()
					: ExtensionPointProperties.DEFAULT_EXCLUDE;
		}

		/**
		 * Gets the {@link ExtensionPoint} priority.
		 * 
		 * @param c the class to get {@link ExtensionPoint} priority of.
		 * @return the class's {@link ExtensionPoint} priority 
		 *   ({@link ExtensionPointProperties#DEFAULT_PRIORITY} will be used in a 
		 *   non-{@link ExtensionPoint} is passed in)
		 */
		public static int getPriority(Class<?> c) {
			ExtensionPointProperties properties = c.getAnnotation(ExtensionPointProperties.class);
			return properties != null ? properties.priority()
					: ExtensionPointProperties.DEFAULT_PRIORITY;
		}
	}
}
