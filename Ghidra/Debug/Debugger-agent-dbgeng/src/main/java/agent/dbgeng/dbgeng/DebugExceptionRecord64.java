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
package agent.dbgeng.dbgeng;

import java.util.Collections;
import java.util.List;

/**
 * Data copied from a {@code EXCEPTION_RECORD64} as defined in {@code winnt.h}.
 * 
 * TODO: Some enums, flags, etc., to help interpret some of the fields.
 */
public class DebugExceptionRecord64 {
	public final int code; // TODO: How to interpret
	public final int flags; // TODO: How to interpret
	public final long record; // TODO: How to interpret
	public final long address;
	public final List<Long> information;

	public DebugExceptionRecord64(int code, int flags, long record, long address,
			List<Long> information) {
		this.code = code;
		this.flags = flags;
		this.record = record;
		this.address = address;
		this.information = Collections.unmodifiableList(information);
	}
}
