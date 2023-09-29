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

import java.net.URL;
import java.util.HashSet;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a place from which {@link Class}s can be obtained
 */
abstract class ClassLocation {

	protected static final String CLASS_EXT = ".class";

	protected final Logger log = LogManager.getLogger(getClass());

	protected Set<Class<?>> classes = new HashSet<>();

	protected abstract void getClasses(Set<Class<?>> set, TaskMonitor monitor)
			throws CancelledException;

	protected void checkForDuplicates(Set<Class<?>> existingClasses) {
		for (Class<?> c : classes) {
			// Note: our class and a matching class in 'existingClasses' will be '==' since the 
			// class loader loaded the class by name--it will always find the same class, in 
			// classpath order.
			if (existingClasses.contains(c)) {
				log.warn(() -> generateMessage(c));
			}
		}
	}

	private String generateMessage(Class<?> c) {
		return String.format("Class defined in multiple locations: %s. Keeping class loaded " +
			"from %s; ignoring class from %s", c, toLocation(c), this);
	}

	private String toLocation(Class<?> clazz) {
		String name = clazz.getName();
		String classAsPath = '/' + name.replace('.', '/') + ".class";
		URL url = clazz.getResource(classAsPath);
		String urlPath = url.getPath();
		int index = urlPath.indexOf(classAsPath);
		return urlPath.substring(0, index);
	}
}
