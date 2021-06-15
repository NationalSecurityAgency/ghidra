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
package ghidra.util;

import java.util.concurrent.locks.Lock;

public class LockHold implements AutoCloseable {

	public static LockHold lock(Lock lock) {
		LockHold hold = new LockHold(lock);
		hold.lock.lock();
		return hold;
	}

	private Lock lock;

	protected LockHold(Lock lock) {
		this.lock = lock;
	}

	@Override
	public void close() {
		this.lock.unlock();
	}
}
