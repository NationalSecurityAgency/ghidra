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
package ghidra.pcode.exec;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeUseropLibraryFactory.UseropLibrary;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

@UseropLibrary(id = "diagnostics", includeAlways = true)
public class DiagnosticsPcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {

	@Override
	@SuppressWarnings("unchecked")
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		return (PcodeUseropLibrary<T>) DiagnosticsPcodeUseropLibrary.INSTANCE;
	}

	public static class DiagnosticsPcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		public static final DiagnosticsPcodeUseropLibrary<?> INSTANCE =
			new DiagnosticsPcodeUseropLibrary<>();

		private DiagnosticsPcodeUseropLibrary() {
		}

		@PcodeUserop
		public void emu_probe(@OpExecutor PcodeExecutor<T> exec, Varnode in) {
			SleighLanguage language = exec.getLanguage();
			String name = in.toString(language);
			T value = exec.getState().getVar(in, Reason.INSPECT);
			byte[] concrete;
			try {
				concrete = exec.getArithmetic().toConcrete(value, Purpose.INSPECT);
			}
			catch (ConcretionError e) {
				concrete = null;
			}
			String concreteString = concrete == null ? null
					: "%s (%s)".formatted(
						NumericUtilities.convertBytesToString(concrete, ":"),
						Utils.bytesToBigInteger(concrete, in.getSize(), language.isBigEndian(),
							false));
			if (value == concrete) {
				Msg.debug(this, "%s = %s".formatted(name, concreteString));
			}
			else if (concrete != null) {
				Msg.debug(this, "%s = %s => %s (%s)".formatted(name, value, concreteString));
			}
			else {
				Msg.debug(this, "%s = %s".formatted(name, value));
			}
		}
	}
}
