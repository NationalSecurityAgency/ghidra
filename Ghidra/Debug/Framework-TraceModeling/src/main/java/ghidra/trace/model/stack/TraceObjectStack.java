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
package ghidra.trace.model.stack;

import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInfo;

/**
 * Represents the execution stack, as unwound into frames by the debugger
 * 
 * <p>
 * Conventionally, if the debugger can also unwind register values, then each frame should present a
 * register bank. Otherwise, the same object presenting this stack should present the register bank.
 * 
 * <p>
 * TODO: Probably remove this. It serves only as a container of {@link TraceObjectStackFrame}, which
 * can be discovered using the schema.
 */
@TraceObjectInfo(
	schemaName = "Stack",
	shortName = "stack",
	attributes = {},
	fixedKeys = {})
public interface TraceObjectStack extends TraceStack, TraceObjectInterface {
}
