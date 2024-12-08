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
package ghidra.app.plugin.core.debug.service.tracermi;

import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.debug.api.tracermi.RemoteParameter;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.trace.model.Trace;

public record RecordRemoteParameter(TraceRmiHandler handler, String name, SchemaName type,
		boolean required, ValueSupplier defaultValue, String display, String description)
		implements RemoteParameter {

	public Object getDefaultValue(Trace trace) {
		OpenTrace open = handler.getOpenTrace(trace);
		if (open == null) {
			throw new IllegalArgumentException("Trace is not from this connection");
		}
		try {
			return defaultValue().get(open);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	public Object getDefaultValue() {
		try {
			return defaultValue().get(ValueDecoder.DEFAULT);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}
}
