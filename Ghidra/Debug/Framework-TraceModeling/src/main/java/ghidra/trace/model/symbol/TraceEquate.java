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
package ghidra.trace.model.symbol;

import java.util.Collection;

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.Enum;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Equate;
import ghidra.trace.model.thread.TraceThread;

/**
 * TODO: Document me
 * 
 * This is like {@link Equate}, except that extending it would prevent references with snaps. Thus,
 * this interface is almost identical except where {@link Address}es are used, a snap is also used.
 */
public interface TraceEquate {
	String getName();

	String getDisplayName();

	long getValue();

	String getDisplayValue();

	int getReferenceCount();

	TraceEquateReference addReference(Range<Long> lifespan, TraceThread thread, Address address,
			int operandIndex);

	TraceEquateReference addReference(Range<Long> lifespan, TraceThread thread, Address address,
			Varnode varnode);

	void setName(String newName);

	Collection<? extends TraceEquateReference> getReferences();

	TraceEquateReference getReference(long snap, TraceThread thread, Address address,
			int operandIndex);

	TraceEquateReference getReference(long snap, TraceThread thread, Address address,
			Varnode varnode);

	boolean hasValidEnum();

	boolean isEnumBased();

	Enum getEnum();

	void delete();
}
