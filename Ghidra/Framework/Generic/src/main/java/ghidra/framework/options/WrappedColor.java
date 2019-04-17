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
package ghidra.framework.options;

import java.awt.Color;

/**
 * An wrapper object for registering Colors as options.
 */

class WrappedColor implements WrappedOption {
	private static final String COLOR = "color";
	private Color color;

	/**
	 * Constructs a WrappedOption for a Color.
	 */
	WrappedColor(Color color) {
		this.color = color;
	}

	/**
	 * Default constructor.
	 * @see java.lang.Object#Object()
	 */
	public WrappedColor() {
		// for reflection
	}

	@Override
	public Object getObject() {
		return color;
	}

	/**
	 * Reads the saved Color information and reconstructs the Color.
	 */
	@Override
	public void readState(SaveState saveState) {
		int rgb = saveState.getInt(COLOR, 0);
		color = new Color(rgb);
	}

	/**
	 * Saves the Color information so that it can be reconstructed.
	 */
	@Override
	public void writeState(SaveState saveState) {
		saveState.putInt(COLOR, color.getRGB());
	}

	@Override
	public OptionType getOptionType() {
		return OptionType.COLOR_TYPE;
	}
}
