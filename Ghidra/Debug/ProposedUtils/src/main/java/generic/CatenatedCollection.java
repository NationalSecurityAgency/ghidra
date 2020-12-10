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
package generic;

import java.util.Collection;
import java.util.Iterator;

import com.google.common.collect.Iterators;

public class CatenatedCollection<E> extends AbstractUnionedCollection<E> {

	public CatenatedCollection(Collection<? extends Collection<? extends E>> collections) {
		super(collections);
	}

	@SafeVarargs
	public CatenatedCollection(Collection<? extends E>... collections) {
		super(collections);
	}

	@Override
	public Iterator<E> iterator() {
		return Iterators.concat(new Iterator<Iterator<? extends E>>() {
			Iterator<? extends Collection<? extends E>> it = collections.iterator();

			@Override
			public boolean hasNext() {
				return it.hasNext();
			}

			@Override
			public Iterator<? extends E> next() {
				return it.next().iterator();
			}
		});
	}
}
