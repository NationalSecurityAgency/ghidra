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
package ghidra.app.decompiler.component;

import java.awt.Color;

import ghidra.app.decompiler.ClangToken;

/**
 * A color provider that returns a specific color.
 */
public class DefaultColorProvider implements ColorProvider {

	private Color color;
	private String prefix;

	/**
	 * Constructor
	 * @param prefix a descriptive prefix used in the {@link #toString()} method
	 * @param color the color
	 */
	DefaultColorProvider(String prefix, Color color) {
		this.prefix = prefix;
		this.color = color;
	}

	@Override
	public Color getColor(ClangToken token) {
		return color;
	}

	@Override
	public String toString() {
		return prefix + ' ' + color;
	}
}
