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

import java.util.Collection;
import java.util.Comparator;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public enum StreamUtils {
	;
	@SuppressWarnings("unchecked")
	public static <T> Stream<T> merge(Collection<? extends Stream<? extends T>> streams,
			Comparator<? super T> comparator) {
		if (streams.size() == 1) {
			return (Stream<T>) streams.iterator().next();
		}
		return StreamSupport.stream(new MergeSortingSpliterator<>(
			streams.stream().map(s -> s.spliterator()).toList(), comparator), false);
	}
}
