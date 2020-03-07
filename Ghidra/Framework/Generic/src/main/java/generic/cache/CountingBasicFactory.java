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
package generic.cache;

import java.util.concurrent.atomic.AtomicInteger;

public abstract class CountingBasicFactory<T> implements BasicFactory<T> {

	/**
	 * A counter for tracking the number of items that have been created.
	 */
	protected AtomicInteger counter = new AtomicInteger();
	protected AtomicInteger disposedCount = new AtomicInteger();

	@Override
	public T create() throws Exception {
		return doCreate(counter.incrementAndGet());
	}

	@Override
	public void dispose(T t) {
		disposedCount.incrementAndGet();
		doDispose(t);
	}

	/**
	 * The method subclass use to create {@link T}s. 
	 * 
	 * @param itemNumber the number of the item being created--
	 * 						<span style="font-size:24px"><b>one-based</b></span>; the first item 
	 *                   	is item <code>1</code>.
	 * @return a new instance of {@link T}.
	 * @throws Exception any Exception encountered during creation
	 */
	public abstract T doCreate(int itemNumber) throws Exception;

	public abstract void doDispose(T t);
}
