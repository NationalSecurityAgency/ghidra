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
package ghidra.util.datastruct;

import java.util.Collection;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * The interface provides a mechanism for clients to pass around an object that is effectively
 * a 'results object', into which data can be placed as it is discovered. 
 * 
 * <P>Historically, clients that load data will return results, once fully loaded, in a 
 * {@link Collection}.  This has the drawback that the discovered data cannot be used until
 * all searching is complete.  This interface can now be passed into such a method (as opposed
 * to be returned by it) so that the client can make use of data as it is discovered.   This 
 * allows for long searching processes to report data as they work. 
 *
 * @param <T> the type
 */
public interface Accumulator<T> extends Iterable<T> {

	public void add(T t);

	public void addAll(Collection<T> collection);

	public boolean contains(T t);

	public Collection<T> get();

	public int size();

	default boolean isEmpty() {
		return size() == 0;
	}

	default Stream<T> stream() {
		return StreamSupport.stream(spliterator(), false);
	}
}
