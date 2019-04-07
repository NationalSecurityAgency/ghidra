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

import java.util.List;
import java.util.concurrent.CopyOnWriteArraySet;

import ghidra.framework.model.DomainFile;

/**
 * Simple static class to keep track of transient domain file/domain objects.
 * When new domain objects are created, they may not have an associated DomainFile.
 * In this case, a DomainFileProxy is created to contain it.  DomainFileProxy objects
 * will add themselves to this Manager whenever a tool is using the associated
 * DomainObject and will remove itself all the tools have released the domainObject.
 */
public class TransientDataManager {
	private TransientDataManager() {
	}

	// Set implementation must be thread safe and not sensitive to the file's name changing
	private static CopyOnWriteArraySet<DomainFileProxy> set = new CopyOnWriteArraySet<>();

	/**
	 * Adds the given transient domain file to the list.
	 * @param domainFile the transient domain file to add to the list
	 */
	public static void addTransient(DomainFileProxy domainFile) {
		// TODO This previously had a change to exclude files which do not need saving.
		// Can't do this since versioned files may get changed later.
		// Find out why files would need to be excluded here.
		set.add(domainFile);
	}

	/**
	 * Removes the given transient domain file from the list.
	 * @param domainFile the transient domain file to remove
	 */
	public static void removeTransient(DomainFileProxy domainFile) {
		set.remove(domainFile);
	}

	/**
	 * Removes all transients from the list.
	 */
	public static void clearAll() {
		set.clear();
	}

	/**
	 * Populates the given array list with all the transients.
	 * @param l the list populate with the transients
	 */
	public static void getTransients(List<DomainFile> l) {
		l.addAll(set);
	}

	/**
	 * Releases all files for the given consumer.
	 * @param consumer the domain file consumer
	 */
	public static void releaseFiles(Object consumer) {
		for (DomainFileProxy df : set) {
			df.release(consumer);
		}
	}
}
