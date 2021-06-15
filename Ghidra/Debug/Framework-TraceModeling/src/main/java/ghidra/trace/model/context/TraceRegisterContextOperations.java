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
package ghidra.trace.model.context;

import java.util.Map.Entry;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.trace.model.TraceAddressSnapRange;

public interface TraceRegisterContextOperations {
	/**
	 * Get the language-defined default value of the register
	 * 
	 * @param language the language
	 * @param register a register in the language
	 * @param address the address from which to read the context
	 * @return the default value, or {@code null} if no default is defined for the parameters
	 */
	RegisterValue getDefaultValue(Language language, Register register, Address address);

	void setValue(Language language, RegisterValue value, Range<Long> lifespan, AddressRange range);

	void removeValue(Language language, Register register, Range<Long> span, AddressRange range);

	RegisterValue getValue(Language language, Register register, long snap, Address address);

	Entry<TraceAddressSnapRange, RegisterValue> getEntry(Language language, Register register,
			long snap, Address address);

	RegisterValue getValueWithDefault(Language language, Register register, long snap,
			Address address);

	AddressSetView getRegisterValueAddressRanges(Language language, Register register, long snap,
			AddressRange within);

	AddressSetView getRegisterValueAddressRanges(Language language, Register register, long snap);

	boolean hasRegisterValueInAddressRange(Language language, Register register, long snap,
			AddressRange within);

	boolean hasRegisterValue(Language language, Register register, long snap);

	void clear(Range<Long> span, AddressRange range);
}
