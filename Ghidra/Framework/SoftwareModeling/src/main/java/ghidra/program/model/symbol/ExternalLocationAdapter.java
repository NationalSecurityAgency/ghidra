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
package ghidra.program.model.symbol;

import java.util.Iterator;

public class ExternalLocationAdapter implements ExternalLocationIterator {

	private final Iterator<ExternalLocation> iterator;

	public ExternalLocationAdapter(Iterator<ExternalLocation> iterator) {
		this.iterator = iterator;	
	}
	
	@Override
	public boolean hasNext() {
		return iterator.hasNext();
	}

	@Override
	public ExternalLocation next() {
		return iterator.next();
	}

	@Override
	public void remove() {
		iterator.remove();
	}

}
