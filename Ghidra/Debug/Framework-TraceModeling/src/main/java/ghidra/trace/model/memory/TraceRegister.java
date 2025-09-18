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
package ghidra.trace.model.memory;

import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectManager;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInfo;
import ghidra.trace.model.thread.TraceThread;

/**
 * A register
 * 
 * <p>
 * There are two conventions for presenting registers and their values. Both are highly recommended:
 * 
 * <ol>
 * <li><b>In the {@link TraceMemoryManager}</b>: If this convention is not implemented by the
 * connector, then the trace database itself will try to convert the object-model tree presentation
 * to it, because the only way to annotate data types and references in registers is to instantiate
 * the appropriate register space. See the manager's documentation for how to set these up.
 * <b>NOTE</b>: The {@link TraceRegisterContainer} for the relevant thread or frame
 * <em>must</em> exist in this convention, even if the tree convention is not presented.</li>
 * <li><b>In the {@link TraceObjectManager}</b>: This convention is required when a register is not
 * known to Ghidra's slaspec, which is certainly the case if the connector falls back to the
 * {@code DATA} processor. It is easiest just to always present the tree. It provides some
 * redundancy in case the memory-manager presentation gets broken, and it allows the user to choose
 * a preferred presentation. In the tree convention, each register is presented with this interface.
 * The name is taken from the object key, the length in bits is given in the attribute
 * {@link #KEY_BITLENGTH}, and the value is given in the attribute
 * {@link TraceObjectInterface#KEY_VALUE}. Alternatively, connectors may present registers as
 * primitive children of the container.</li>
 * </ol>
 * 
 * <p>
 * Some connectors may present registers in groups. To support this, there is an explicit
 * {@link TraceRegisterContainer}. Ordinarily, the client would use the schema to detect a
 * "container" of {@link TraceRegister}; however, that is not sufficient with groups. The root
 * container (per thread or per frame) is marked as the {@link TraceRegisterContainer}. The
 * connector may then organize the registers into groups, each group being a plain
 * {@link TraceObject}, so long as each {@link TraceRegister} is a successor to the register
 * container.
 */
@TraceObjectInfo(
	schemaName = "Register",
	shortName = "register",
	attributes = {
		TraceRegister.KEY_BITLENGTH,
		TraceRegister.KEY_STATE,
	},
	fixedKeys = {
		TraceRegister.KEY_BITLENGTH,
	})
public interface TraceRegister extends TraceObjectInterface {
	String KEY_BITLENGTH = "_length";
	String KEY_STATE = "_state";

	TraceThread getThread();

	String getName();

	int getBitLength(long snap);

	default int getByteLength(long snap) {
		return (getBitLength(snap) + 7) / 8;
	}

	void setValue(Lifespan lifespan, byte[] value);

	byte[] getValue(long snap);

	void setState(Lifespan lifespan, TraceMemoryState state);

	TraceMemoryState getState(long snap);

	// TODO: getAddress()?
	// Would provide info for memory-mapped registers.
	// Could also communicate structure / aliasing.
}
