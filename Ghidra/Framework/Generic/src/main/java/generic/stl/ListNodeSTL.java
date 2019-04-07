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
package generic.stl;

public class ListNodeSTL<T> {
	ListNodeSTL<T> next;
	ListNodeSTL<T> prev;
	public T value;
	public StackTraceElement[] stackUse;
	public ListNodeSTL(ListNodeSTL<T> prev, ListNodeSTL<T> next, T value) {
		this.prev = prev;
		this.next = next;
		this.value = value;
	}
	public ListNodeSTL() {
		next = this;
		prev = this;
		value = null;
	}
}
