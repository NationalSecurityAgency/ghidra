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
package ghidra.program.emulation;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeUseropLibraryFactory.UseropLibrary;

@UseropLibrary("xtensa")
public class XtensaPcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {
	@Override
	public <T> PcodeUseropLibrary<T> create(SleighLanguage language,
			PcodeArithmetic<T> arithmetic) {
		return new XtensaPcodeUseropLibrary<>(language);
	}

	public static class IntStack {
		public static final int INIT_SIZE = 16;
		private int[] vals = new int[INIT_SIZE];
		private int size = 0;

		public void push(int value) {
			if (size == vals.length) {
				grow();
			}
			vals[size] = value;
			size++;
		}

		public int pop() {
			if (size == 0) {
				throw new LowlevelError("stack is empty");
			}
			size--;
			return vals[size];
		}

		private void grow() {
			int[] vals = new int[this.vals.length * 2];
			System.arraycopy(this.vals, 0, vals, 0, this.vals.length);
			this.vals = vals;
		}
	}

	public static class XtensaPcodeUseropLibrary<T> extends AnnotatedPcodeUseropLibrary<T> {
		private final static int TYPE_COUNT = 0;
		private final static int TYPE_VALUE = 1;

		private final IntStack stack = new IntStack();

		public XtensaPcodeUseropLibrary(SleighLanguage language) {
			SleighPcodeUseropDefinition.Factory factory =
				new SleighPcodeUseropDefinition.Factory(language);

			putOp(factory.define("rotateRegWindow").params("callinc").body(args -> """
					__pushCount(callinc);
					if (callinc == 0) goto <done>;
					if (callinc == 1) goto <push4>;
					if (callinc == 2) goto <push8>;
					if (callinc == 3) goto <push12>;
					__lle_invalidCallinc(callinc);
					<push4>
					""" + genPushN(4) + """
					goto <done>;
					<push8>
					""" + genPushN(8) + """
					goto <done>;
					<push12>
					""" + genPushN(12) + """
					<done>
					""").build());

			putOp(factory.define("restoreRegWindow").body(args -> """
					callinc:4 = (a0 >> 30) & 0x3;
					__popCount(callinc);
					if (callinc == 0) goto <done>;
					if (callinc == 1) goto <pop4>;
					if (callinc == 2) goto <pop8>;
					if (callinc == 3) goto <pop12>;
					<pop4>
					""" + genPopN(4) + """
					goto <done>;
					<pop8>
					""" + genPopN(8) + """
					goto <done>;
					<pop12>
					""" + genPopN(12) + """
					<done>
					""").build());
		}

		protected String genPushN(int n) {
			StringBuilder buf = new StringBuilder();
			int i = 0;
			for (; i < n; i++) {
				buf.append("  __pushValue(a%d);\n".formatted(i));
			}
			for (; i < 16; i++) {
				buf.append("  a%d = a%d;\n".formatted(i - n, i));
			}
			return buf.toString();
		}

		protected String genPopN(int n) {
			StringBuilder buf = new StringBuilder();
			int i = 15;
			for (; i >= n; i--) {
				buf.append("  a%d = a%d;\n".formatted(i, i - n));
			}
			for (; i >= 0; i--) {
				buf.append("  a%d = __popValue();\n".formatted(i));
			}
			return buf.toString();
		}

		@PcodeUserop(functional = true, hasSideEffects = false)
		public void __lle_invalidCallinc(int callinc) {
			throw new LowlevelError(
				"rotateRegWindow: invalid value for CALLINC (0x%x)".formatted(callinc));
		}

		@PcodeUserop(functional = true)
		public void __pushCount(int count) {
			stack.push(TYPE_COUNT);
			stack.push(count);
		}

		@PcodeUserop(functional = true)
		public void __popCount(int count) {
			int type = stack.pop();
			int value = stack.pop();
			if (type != TYPE_COUNT) {
				throw new LowlevelError("Popped count, but got a value");
			}
			if (value != count) {
				throw new LowlevelError("""
						restoreRegWindow: return address CALLINC (%d) does not match last entry \
						CALLINC value (%d)""".formatted(count, value));
			}
		}

		@PcodeUserop(functional = true)
		public void __pushValue(int value) {
			stack.push(TYPE_VALUE);
			stack.push(value);
		}

		@PcodeUserop(functional = true)
		public int __popValue() {
			int type = stack.pop();
			int value = stack.pop();
			if (type != TYPE_VALUE) {
				throw new LowlevelError("Popped value, but got a count");
			}
			return value;
		}

		@PcodeUserop(canInline = true)
		public void swap4() {
		}

		@PcodeUserop(canInline = true)
		public void swap8() {
		}

		@PcodeUserop(canInline = true)
		public void swap12() {
		}

		@PcodeUserop(canInline = true)
		public void restore4() {
		}

		@PcodeUserop(canInline = true)
		public void restore8() {
		}

		@PcodeUserop(canInline = true)
		public void restore12() {
		}
	}
}
