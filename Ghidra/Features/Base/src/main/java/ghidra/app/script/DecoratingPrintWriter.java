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
package ghidra.app.script;

import java.awt.Color;
import java.io.PrintWriter;
import java.io.Writer;

/**
 * A print writer that allows clients to specify the text color.
 */
public abstract class DecoratingPrintWriter extends PrintWriter {

	public DecoratingPrintWriter(Writer out) {
		super(out);
	}

	/**
	 * Print a line of text with the given color.
	 * @param s the text
	 * @param c the color
	 */
	public abstract void println(String s, Color c);

	/**
	 * Print text with the given color.
	 * @param s the text
	 * @param c the color
	 */
	public abstract void print(String s, Color c);
}
