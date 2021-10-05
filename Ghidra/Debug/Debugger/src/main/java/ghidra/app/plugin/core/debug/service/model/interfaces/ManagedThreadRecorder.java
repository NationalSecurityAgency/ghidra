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
package ghidra.app.plugin.core.debug.service.model.interfaces;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.core.debug.mapping.DebuggerRegisterMapper;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.trace.model.thread.TraceThread;

public interface ManagedThreadRecorder extends AbstractTraceRecorder {

	public TargetThread getTargetThread();

	public TraceThread getTraceThread();

	public void offerRegisters(TargetRegisterBank added);

	public void removeRegisters(TargetRegisterBank removed);

	public void offerThreadRegion(TargetMemoryRegion region);

	public void recordRegisterValue(TargetRegister targetRegister, byte[] value);

	public void recordRegisterValues(TargetRegisterBank bank, Map<String, byte[]> updates);

	public void invalidateRegisterValues(TargetRegisterBank bank);

	public boolean objectRemoved(TargetObject removed);

	public void stateChanged(TargetExecutionState state);

	public void regMapperAmended(DebuggerRegisterMapper rm, TargetRegister reg, boolean b);

	public CompletableFuture<Void> doFetchAndInitRegMapper(TargetRegisterBank parent);

	public ManagedStackRecorder getStackRecorder();

}
