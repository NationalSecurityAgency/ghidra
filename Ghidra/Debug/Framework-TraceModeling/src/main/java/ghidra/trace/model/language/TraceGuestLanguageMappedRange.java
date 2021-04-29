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
package ghidra.trace.model.language;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Language;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface TraceGuestLanguageMappedRange {
	Language getHostLanguage();

	AddressRange getHostRange();

	Language getGuestLanguage();

	AddressRange getGuestRange();

	Address mapHostToGuest(Address hostAddress);

	Address mapGuestToHost(Address guestAddress);

	void delete(TaskMonitor monitor) throws CancelledException;
}
