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
package ghidra.framework.data;

import java.io.IOException;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class OpenedDomainFile<T extends DomainObject> implements AutoCloseable {
	public final T content;

	public static <T extends DomainObject> OpenedDomainFile<T> open(Class<T> contentType,
			DomainFile file, boolean okToUpgrade, boolean okToRecover, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		return new OpenedDomainFile<>(contentType, file, okToUpgrade, okToRecover, monitor);
	}

	public static <T extends DomainObject> OpenedDomainFile<T> open(Class<T> contentType,
			DomainFile file, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		return new OpenedDomainFile<>(contentType, file, false, false, monitor);
	}

	public OpenedDomainFile(Class<T> contentType, DomainFile file, boolean okToUpgrade,
			boolean okToRecover, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		if (!contentType.isAssignableFrom(file.getDomainObjectClass())) {
			throw new ClassCastException("file " + file + " does not contain " + contentType +
				". got " + file.getDomainObjectClass() + " instead.");
		}
		content = contentType.cast(file.getDomainObject(this, okToUpgrade, okToRecover, monitor));
	}

	@Override
	public void close() {
		if (content != null) {
			content.release(this);
		}
	}
}
