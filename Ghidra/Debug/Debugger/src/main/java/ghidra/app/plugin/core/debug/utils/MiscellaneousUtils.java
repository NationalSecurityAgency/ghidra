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
package ghidra.app.plugin.core.debug.utils;

import java.awt.Component;
import java.awt.event.*;
import java.beans.PropertyEditor;
import java.math.BigInteger;
import java.util.Map;
import java.util.function.Function;

import ghidra.app.plugin.core.debug.gui.action.LocationTrackingSpec;
import ghidra.framework.options.*;
import ghidra.program.model.address.AddressRange;
import ghidra.util.MathUtilities;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;

public enum MiscellaneousUtils {
	;

	public static final String HEX_BIT64 = "0x" + BigInteger.ONE.shiftLeft(64).toString(16);

	/**
	 * Obtain a swing component which may be used to edit the property.
	 * 
	 * <p>
	 * This has been shamelessly stolen from {@link EditorState#getEditorComponent()}, which seems
	 * entangled with Ghidra's whole options system. I think this portion could be factored out.
	 * 
	 * @param editor the editor for which to obtain an interactive component for editing
	 * @return the component
	 */
	public static Component getEditorComponent(PropertyEditor editor) {
		if (editor.supportsCustomEditor()) {
			return editor.getCustomEditor();
		}
		if (editor.getValue() instanceof Boolean) {
			return new PropertyBoolean(editor);
		}
		if (editor.getTags() != null) {
			return new PropertySelector(editor);
		}
		if (editor.getAsText() != null) {
			return new PropertyText(editor);
		}

		Class<? extends PropertyEditor> clazz = editor.getClass();
		String clazzName = clazz.getSimpleName();
		if (clazzName.startsWith("String")) {
			// Most likely some kind of string editor with a null value.  Just use a string 
			// property and let the value be empty.
			return new PropertyText(editor);
		}

		throw new IllegalStateException(
			"Ghidra does not know how to use PropertyEditor: " + editor.getClass().getName());
	}

	public static void rigFocusAndEnter(Component c, Runnable runnable) {
		c.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				runnable.run();
			}
		});
		c.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					runnable.run();
				}
			}
		});
	}

	public static <T> void collectUniqueInstances(Class<T> cls, Map<String, T> map,
			Function<T, String> keyFunc) {
		// This is wasteful. Existing instances will be re-instantiated and thrown away
		for (T t : ClassSearcher.getInstances(cls)) {
			String key = keyFunc.apply(t);
			T exists = map.get(key);
			if (exists != null) {
				if (exists.getClass().equals(t.getClass())) {
					continue;
				}
				Msg.error(LocationTrackingSpec.class,
					cls.getSimpleName() + " conflict over key: " + key);
			}
			map.put(key, t);
		}
	}

	public static long lengthMin(long a, long b) {
		if (a == 0) {
			return b;
		}
		if (b == 0) {
			return a;
		}
		return MathUtilities.unsignedMin(a, b);
	}

	public static String lengthToString(long length) {
		return length == 0 ? HEX_BIT64 : ("0x" + Long.toHexString(length));
	}

	/**
	 * Parses a value from 1 to 1<<64. Any value outside the range is "clipped" into the range.
	 * 
	 * <p>
	 * Note that a returned value of 0 indicates 2 to the power 64, which is just 1 too high to fit
	 * into a 64-bit long.
	 * 
	 * @param text the text to parse
	 * @param defaultVal the default value should parsing fail altogether
	 * @return the length, where 0 indicates {@code 1 << 64}.
	 */
	public static long parseLength(String text, long defaultVal) {
		text = text.trim();
		String post;
		int radix;
		if (text.startsWith("-")) {
			return 0;
		}
		if (text.startsWith("0x")) {
			post = text.substring(2);
			radix = 16;
		}
		else {
			post = text;
			radix = 10;
		}
		BigInteger bi;
		try {
			bi = new BigInteger(post, radix);
		}
		catch (NumberFormatException e) {
			return defaultVal;
		}
		if (bi.equals(BigInteger.ZERO)) {
			return 1;
		}
		if (bi.bitLength() > 64) {
			return 0; // indicates 2**64, the max length
		}
		return bi.longValue(); // Do not use exact. It checks bitLength again, and considers sign.
	}

	public static long revalidateLengthByRange(AddressRange range, long length) {
		long maxLength =
			range.getAddressSpace().getMaxAddress().subtract(range.getMinAddress()) + 1;
		return MiscellaneousUtils.lengthMin(length, maxLength);
	}
}
