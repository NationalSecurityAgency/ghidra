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
package ghidra.pcode.emu.stdoplib;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeUseropLibraryFactory.UseropLibrary;

// This treads on GP-4240 a bit. Still, enough to demonstrate the framework can support it.
@UseropLibrary("trig")
public class TrigPcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {

	@Override
	@SuppressWarnings("unchecked")
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		return (PcodeUseropLibrary<T>) TrigPcodeUseropLibrary.INSTANCE;
	}

	public static class TrigPcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		public static final TrigPcodeUseropLibrary<?> INSTANCE = new TrigPcodeUseropLibrary<>();

		@PcodeUserop(functional = true)
		public float sin(float a) {
			return (float) Math.sin(a);
		}

		// GP-5339: This won't work until we support overloaded userops
		@PcodeUserop(functional = true)
		public double sin(double a) {
			return Math.sin(a);
		}
	}
}
