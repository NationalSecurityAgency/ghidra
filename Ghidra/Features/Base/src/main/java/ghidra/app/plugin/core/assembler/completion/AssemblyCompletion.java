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
package ghidra.app.plugin.core.assembler.completion;

import java.awt.Color;

/**
 * A generic class for all items listed by the autocompleter
 */
public class AssemblyCompletion implements Comparable<AssemblyCompletion> {
	private final String text;
	private final String display;
	private final Color color;
	protected int order;

	public AssemblyCompletion(String text, String display, Color color, int order) {
		this.text = text;
		this.display = display;
		this.color = color;
		this.order = order;
	}

	/**
	 * Get the foreground color for the item
	 * 
	 * @return the color
	 */
	public Color getColor() {
		return color;
	}

	/**
	 * Get the (possibly HTML) text to display for the item
	 * 
	 * @return the text
	 */
	public String getDisplay() {
		return display;
	}

	/**
	 * Get the text to insert when the item is activated
	 * 
	 * @return the text
	 */
	public String getText() {
		return text;
	}

	/**
	 * Override this to permit activation by default, i.e., on CTRL-SPACE
	 * 
	 * @return true to permit defaulting, false to prevent it
	 */
	public boolean getCanDefault() {
		return false;
	}

	@Override
	public String toString() {
		return getDisplay();
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof AssemblyCompletion)) {
			return false;
		}
		return this.toString().equals(o.toString());
	}

	@Override
	public int hashCode() {
		return this.toString().hashCode();
	}

	@Override
	public int compareTo(AssemblyCompletion that) {
		if (this.order != that.order) {
			return this.order - that.order;
		}
		return this.toString().compareTo(that.toString());
	}
}
