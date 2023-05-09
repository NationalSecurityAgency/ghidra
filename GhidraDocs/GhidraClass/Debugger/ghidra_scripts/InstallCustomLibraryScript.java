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
import ghidra.app.plugin.core.debug.service.emulation.*;
import ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerAccess;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.pcode.exec.PcodeUseropLibrary;

public class InstallCustomLibraryScript extends GhidraScript implements FlatDebuggerAPI {
	public static class CustomBytesDebuggerPcodeEmulator extends BytesDebuggerPcodeEmulator {
		private CustomBytesDebuggerPcodeEmulator(PcodeDebuggerAccess access) {
			super(access);
		}

		@Override
		protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
			return super.createUseropLibrary()
					.compose(new ModelingScript.SleighStdLibPcodeUseropLibrary<>(
						(SleighLanguage) access.getLanguage()));
		}
	}

	public static class CustomBytesDebuggerPcodeEmulatorFactory
			extends BytesDebuggerPcodeEmulatorFactory {
		@Override
		public DebuggerPcodeMachine<?> create(PcodeDebuggerAccess access) {
			return new CustomBytesDebuggerPcodeEmulator(access);
		}
	}

	@Override
	protected void run() throws Exception {
		getEmulationService().setEmulatorFactory(new CustomBytesDebuggerPcodeEmulatorFactory());
	}
}
