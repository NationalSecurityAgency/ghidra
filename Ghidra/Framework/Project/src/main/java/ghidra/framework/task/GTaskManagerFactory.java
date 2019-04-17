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
package ghidra.framework.task;

import generic.concurrent.GThreadPool;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.util.exception.AssertException;

import java.util.Map;
import java.util.WeakHashMap;

/**
 * Factory class managing a single GTaskManager for an UndoableDomainObject.
 * 
 */
public class GTaskManagerFactory {
	private static Map<UndoableDomainObject, GTaskManager> map =
		new WeakHashMap<UndoableDomainObject, GTaskManager>();

	/**
	 * Returns the one GTaskManager for the domainObject. A new GTaskManager will be created if
	 * one does not already exist for the domainObject.  
	 * 
	 * @param domainObject the domainObject for which to get a GTaskManager.
	 * @return the GTaskManager for the given domainObject.
	 */
	public static GTaskManager getTaskManager(UndoableDomainObject domainObject) {
		if (domainObject.isClosed()) {
			throw new AssertException("Attempted to get a TaskManger for a closed domain object");
		}
		GTaskManager gTaskManager = map.get(domainObject);
		if (gTaskManager == null) {
			GThreadPool sharedThreadPool = GThreadPool.getSharedThreadPool("Program Thread");
			gTaskManager = new GTaskManager(domainObject, sharedThreadPool);
			map.put(domainObject, gTaskManager);
		}
		return gTaskManager;
	}

	static void domainObjectClosed(UndoableDomainObject domainObject) {
		map.remove(domainObject);
	}
}
