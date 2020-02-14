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

	final Logger log = LogManager.getLogger(getClass());

	protected Set<Class<?>> classes = new HashSet<>();

	abstract void getClasses(Set<Class<?>> set, TaskMonitor monitor) throws CancelledException;

	void checkForDuplicates(Set<Class<?>> existingClasses) {
		if (!log.isTraceEnabled()) {
			return;
		}

		for (Class<?> c : classes) {
			if (existingClasses.contains(c)) {
				Module module = c.getModule();
				module.toString();
				log.trace("Attempting to load the same class twice: {}.  " +
					"Keeping loaded class ; ignoring class from {}", c, this);
				return;
			}
		}
	}

}
