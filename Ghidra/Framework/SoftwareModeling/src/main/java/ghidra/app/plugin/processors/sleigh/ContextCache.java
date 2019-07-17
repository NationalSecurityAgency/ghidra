/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.processors.sleigh;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;

import java.math.BigInteger;
import java.util.Arrays;

public class ContextCache {
	private int context_size = 0;
	private Register contextBaseRegister = null;

	private BigInteger lastContextValue;
	private int[] lastContextWords;

	public ContextCache() {
	}

	public void registerVariable(Register register) {
		context_size = (register.getBaseRegister().getMinimumByteSize() + 3) / 4;
		contextBaseRegister = register.getBaseRegister();
	}

	public int getContextSize() {
		return context_size;
	}

	public void getContext(ProcessorContextView ctx, int[] buf) {
		if (contextBaseRegister == null) {
			return;
		}
		RegisterValue contextRegValue = ctx.getRegisterValue(contextBaseRegister);
		if (contextRegValue == null) {
			Arrays.fill(buf, 0);
			return;
		}
		BigInteger contextValue = contextRegValue.getUnsignedValueIgnoreMask();
		int[] words = getWords(contextValue);
		for (int i = 0; i < buf.length; i++) {
			buf[i] = words[i];
		}
	}

	private synchronized int[] getWords(BigInteger value) {
		if (value.equals(lastContextValue)) {
			return lastContextWords;
		}

		int[] words = new int[context_size];
		byte[] bytes = value.toByteArray();
		int byteIndexDiff = context_size * 4 - bytes.length;
		for (int i = 0; i < context_size; i++) {
			int byteIndex = 4 * i - byteIndexDiff;
			int word = getByte(bytes, byteIndex);
			for (int j = 1; j < 4; j++) {
				word = (word << 8) | getByte(bytes, byteIndex + j);
			}
			words[i] = word;
		}
		lastContextValue = value;
		lastContextWords = words;
		return words;
	}

	private int getByte(byte[] bytes, int index) {
		if (index < 0 || index > bytes.length) {
			return 0;
		}
		return bytes[index] & 0xff;
	}

	private void putInt(byte[] bytes, int index, int value) {
		for (int i = 3; i >= 0; i--) {
			bytes[index + i] = (byte) value;
			value >>= 8;
		}
	}

//	public void setContext(ProcessorContext ctx,Address addr, int num, int mask, int value) {
//		BigInteger contextValue = ctx.getValue(contextBaseRegister, addr, false);
//		int[] context = getWords(contextValue);
//		if (context == null) {
//			context = new int[context_size];
//			getContext(ctx, context);
//		}
//		context[num] = (context[num] & ~mask) | value;
//		byte[] bytes = new byte[context_size*4];
//		for(int i=0;i<context_size;i++) {
//			putInt(bytes, i*4, context[i]);
//		}
//		ctx.setValue(contextBaseRegister, addr, new BigInteger(bytes));
//	}
	public void setContext(ProcessorContext ctx, Address addr, int num, int mask, int value) {
		if (ctx instanceof DisassemblerContext) {
			DisassemblerContext context = (DisassemblerContext) ctx;
			int byteSize = context_size * 4;
			byte[] bytes = new byte[2 * byteSize];
			putInt(bytes, byteSize + num * 4, value);
			putInt(bytes, num * 4, mask);
			RegisterValue registerValue = new RegisterValue(contextBaseRegister, bytes);
			context.setFutureRegisterValue(addr, registerValue);
		}
	}
}
