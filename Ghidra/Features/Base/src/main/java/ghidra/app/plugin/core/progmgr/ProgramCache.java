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
package ghidra.app.plugin.core.progmgr;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import ghidra.framework.data.DomainObjectFileListener;
import ghidra.framework.model.*;
import ghidra.program.model.listing.Program;
import ghidra.util.timer.GTimerCache;

/**
 * Class for doing time based Program caching. 
 * <P>
 * Caching programs has some unique challenges because
 * of the way they are shared using a consumer concept. 
 * Program instances are shared even if unrelated clients open
 * them. Each client using a program registers its use by giving it a 
 * unique consumer object. When done with the program, the client removes its consumer. When the 
 * last consumer is removed, the program instance is closed.
 * <P>
 * When a program is put into the cache, the cache adds itself as a consumer on the program, 
 * effectively keeping it open even if all clients release it. Further, when an entry expires
 * the cache removes itself as a consumer. A race condition can occur when a client attempts to 
 * retrieve a program from the cache and add itself as a consumer, while the entry's expiration is  
 * being processed. Specifically, there may be a small window where there are no consumers on that 
 * program, causing it to be closed. However, since accessing the program will renew its expiration
 * time, it is very unlikely to happen, except for debugging scenarios.
 * <P>
 * Also, because Program instances can change their association from one DomainFile to another
 * (Save As), we need to add a listener to the program to detect this. If this occurs on
 * a program in the cache, we simple remove it from the cache instead of trying to fix it. 
 */
class ProgramCache extends GTimerCache<ProgramLocator, Program> {
	private Map<Program, ProgramFileListener> listenerMap = new HashMap<>();

	/**
	 * Constructs new ProgramCache with a duration for keeping programs open and a maximum
	 * number of programs to cache.
	 * @param duration the time that a program will remain in the cache without being
	 * accessed (accessing a cached program resets its time)
	 * @param capacity the maximum number of programs in the cache before least recently used
	 * programs are removed.
	 */
	public ProgramCache(Duration duration, int capacity) {
		super(duration, capacity);
	}

	@Override
	protected void valueAdded(ProgramLocator key, Program program) {
		program.addConsumer(this);
		ProgramFileListener listener = new ProgramFileListener(key);
		program.addDomainFileListener(listener);
		program.addListener(listener);
		listenerMap.put(program, listener);
	}

	@Override
	protected void valueRemoved(ProgramLocator locator, Program program) {
		// whenever programs are removed from the cache, we need to remove the cache as a consumer 
		// and remove the file changed listener
		ProgramFileListener listener = listenerMap.remove(program);
		program.removeDomainFileListener(listener);
		program.removeListener(listener);
		program.release(this);
	}

	@Override
	protected boolean shouldRemoveFromCache(ProgramLocator locator, Program program) {
		// Only remove the program from the cache if it is not being used by anyone else. The idea
		// is that if it is still being used, it is more likely to be needed again by some other
		// client.
		//
		// Note: when a program is purged due to the cache size limit, this method will not be called 
		return program.getConsumerList().size() <= 1;
	}

	/**
	 * DomainObjectFileListener for programs in the cache. If a program instance has its DomainFile 
	 * changed (e.g., 'Save As' action), then the cache mapping is incorrect as it sill has the
	 * program instance associated with its old DomainFile. So we need to add a listener to 
	 * recognize when this occurs. If it does, we simply remove the entry from the cache. Also,
	 * we need to remove any programs from the cache if changes are made to avoid questions about
	 * who is responsible for saving changed programs that only live in the cache.
	 */
	class ProgramFileListener implements DomainObjectFileListener, DomainObjectListener {
		private ProgramLocator key;

		ProgramFileListener(ProgramLocator key) {
			this.key = key;
		}

		@Override
		public void domainFileChanged(DomainObject object) {
			remove(key);
		}

		@Override
		public void domainObjectChanged(DomainObjectChangedEvent ev) {
			remove(key);
		}
	}
}
