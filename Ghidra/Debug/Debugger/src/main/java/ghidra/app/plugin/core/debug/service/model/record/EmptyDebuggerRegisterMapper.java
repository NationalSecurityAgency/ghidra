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
package ghidra.app.plugin.core.debug.service.model.record;

import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.DebuggerRegisterMapper;
import ghidra.app.plugin.core.debug.register.RegisterTypeInfo;
import ghidra.dbg.target.TargetRegister;
import ghidra.program.model.lang.Register;

public class EmptyDebuggerRegisterMapper implements DebuggerRegisterMapper {
	@Override
	public TargetRegister getTargetRegister(String name) {
		return null;
	}

	@Override
	public Register getTraceRegister(String name) {
		return null;
	}

	@Override
	public TargetRegister traceToTarget(Register register) {
		return null;
	}

	@Override
	public Register targetToTrace(TargetRegister tReg) {
		return null;
	}

	@Override
	public RegisterTypeInfo getDefaultTypeInfo(Register lReg) {
		return null;
	}

	@Override
	public Set<Register> getRegistersOnTarget() {
		return Set.of();
	}

	@Override
	public void targetRegisterAdded(TargetRegister register) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void targetRegisterRemoved(TargetRegister register) {
		throw new UnsupportedOperationException();
	}
}
