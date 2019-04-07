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
package ghidra.util.datastruct;

/**
 * Creates a fixed size stack.
 * The oldest (or deepest) item on the stack
 * will be removed when the max size is achieved.
 */
public class FixedSizeStack<E> extends Stack<E> {

	private int maxSize;

	/**
	 * Creates a fixed size stack with the specified
	 * max size.
	 * @param maxSize the max size of the stack
	 */
	public FixedSizeStack(int maxSize) {
		super();
		this.maxSize = maxSize;
	}

	@Override
	public E push(E item) {
		if (size() > maxSize) {
			list.remove(0);
		}
		return super.push(item);
	}

	@Override
	public void add(E item) {
		if (size() > maxSize) {
			list.remove(0);
		}
		super.add(item);
	}

	public E remove(int index) {
		return list.remove(index);
	}
}
