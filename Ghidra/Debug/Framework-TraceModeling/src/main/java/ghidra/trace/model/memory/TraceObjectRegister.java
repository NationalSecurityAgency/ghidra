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

import ghidra.dbg.target.TargetRegister;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.TraceObjectInterface;
import ghidra.trace.model.target.annot.TraceObjectInfo;
import ghidra.trace.model.thread.TraceObjectThread;

@TraceObjectInfo(
	// NB. Originally meant to describe the register, it now also describes its value
	targetIf = TargetRegister.class,
	shortName = "register",
	fixedKeys = {
		TargetRegister.BIT_LENGTH_ATTRIBUTE_NAME
	})
public interface TraceObjectRegister extends TraceObjectInterface {
	String KEY_STATE = "_state";

	TraceObjectThread getThread();

	String getName();

	int getBitLength();

	default int getByteLength() {
		return (getBitLength() + 7) / 8;
	}

	void setValue(Lifespan lifespan, byte[] value);

	byte[] getValue(long snap);

	void setState(Lifespan lifespan, TraceMemoryState state);

	TraceMemoryState getState(long snap);

	// TODO: getAddress()?
	// Would provide info for memory-mapped registers.
	// Could also communicate structure / aliasing.
}
