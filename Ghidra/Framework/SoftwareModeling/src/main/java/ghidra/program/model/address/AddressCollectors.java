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
package ghidra.program.model.address;

import java.util.Set;
import java.util.function.*;
import java.util.stream.Collector;

/**
 * Utilities for using addresses and ranges in streams
 */
public class AddressCollectors {

	/**
	 * Union a stream of address ranges into a single mutable address set
	 * 
	 * @return the address set
	 */
	public static Collector<AddressRange, AddressSet, AddressSet> toAddressSet() {
		return new Collector<>() {
			@Override
			public Supplier<AddressSet> supplier() {
				return AddressSet::new;
			}

			@Override
			public BiConsumer<AddressSet, AddressRange> accumulator() {
				return AddressSet::add;
			}

			@Override
			public BinaryOperator<AddressSet> combiner() {
				return (s1, s2) -> {
					s1.add(s2);
					return s1;
				};
			}

			@Override
			public Function<AddressSet, AddressSet> finisher() {
				return Function.identity();
			}

			@Override
			public Set<Characteristics> characteristics() {
				return Set.of();
			}
		};
	}
}
