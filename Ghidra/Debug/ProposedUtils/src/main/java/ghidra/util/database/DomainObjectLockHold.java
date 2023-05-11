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
package ghidra.util.database;

import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectLockedException;

/**
 * A hold on the lock for a domain object, obtained via {@link #lock(DomainObject, String)} or
 * {@link #forceLock(DomainObject, boolean, String)}
 * 
 * <p>
 * This is designed for use in a {@code try-with-resources} block to ensure the timely release of
 * the lock even in exceptional conditions, as in:
 * 
 * <pre>
 * try (DomainObjectLockHold hold = DomainObjectLockHold.lock("Demonstration")) {
 * 	// Do stuff while holding the lock
 * }
 * </pre>
 */
public interface DomainObjectLockHold extends AutoCloseable {

	/**
	 * Wrapper for {@link DomainObject#lock(String)}
	 * 
	 * @param object the object
	 * @param reason as in {@link DomainObject#lock(String)}
	 * @return the hold, which should be used in a {@code try-with-resources} block
	 * @throws DomainObjectLockedException if the lock could not be obtained
	 */
	static DomainObjectLockHold lock(DomainObject object, String reason) {
		if (object.lock(reason)) {
			return new DefaultHold(object);
		}
		throw new DomainObjectLockedException("Could not get lock");
	}

	/**
	 * Wrapper for {@link DomainObject#forceLock(boolean, String)}
	 * 
	 * @param object the object
	 * @param rollback as in {@link DomainObject#forceLock(boolean, String)}
	 * @param reason as in {@link DomainObject#forceLock(boolean, String)}
	 * @return the hold, which should be used in a {@code try-with-resources} block
	 */
	static DomainObjectLockHold forceLock(DomainObject object, boolean rollback, String reason) {
		object.forceLock(rollback, reason);
		return new DefaultHold(object);
	}

	class DefaultHold implements DomainObjectLockHold {
		final DomainObject object;

		public DefaultHold(DomainObject object) {
			this.object = object;
		}

		@Override
		public void close() throws Exception {
			object.unlock();
		}
	}
}
