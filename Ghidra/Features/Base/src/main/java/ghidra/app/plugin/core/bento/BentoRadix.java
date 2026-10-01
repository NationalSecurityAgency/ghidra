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
package ghidra.app.plugin.core.bento;

public enum BentoRadix {
	/** Use decimal (default) */
	DEC("dec", 10, "%d"),
	/** Use upper-case hexadecimal */
	HEX_UPPER("HEX", 16, "%X"),
	/** Use lower-case hexadecimal */
	HEX_LOWER("hex", 16, "%x");

	/** The default radix (decimal) */
	public static final BentoRadix DEFAULT = DEC;

	/**
	 * Get the radix specified by the given string
	 * 
	 * @param s the name of the specified radix
	 * @return the radix
	 */
	public static BentoRadix fromStr(String s) {
		return switch (s) {
			case "dec" -> DEC;
			case "HEX" -> HEX_UPPER;
			case "hex" -> HEX_LOWER;
			default -> DEFAULT;
		};
	}

	public final String name;
	public final int n;
	public final String fmt;

	private BentoRadix(String name, int n, String fmt) {
		this.name = name;
		this.n = n;
		this.fmt = fmt;
	}

	public String format(long time) {
		return fmt.formatted(time);
	}

	public long decode(String nm) {
		if (nm.startsWith("0x") || nm.startsWith("0X") ||
			nm.startsWith("-0x") || nm.startsWith("-0X")) {
			return Long.parseLong(nm, 16);
		}
		if (nm.startsWith("0n") || nm.startsWith("0N") ||
			nm.startsWith("-0n") || nm.startsWith("-0N")) {
			return Long.parseLong(nm, 10);
		}
		return Long.parseLong(nm, n);
	}
}

