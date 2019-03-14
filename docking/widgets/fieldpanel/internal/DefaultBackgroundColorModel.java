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
package docking.widgets.fieldpanel.internal;

import java.awt.Color;
import java.math.BigInteger;

import docking.widgets.fieldpanel.support.BackgroundColorModel;


public class DefaultBackgroundColorModel implements BackgroundColorModel {
	private Color backgroundColor;
	
	public DefaultBackgroundColorModel(Color backgroundColor) {
		this.backgroundColor = backgroundColor;
	}

	public Color getBackgroundColor(int index) {
		return backgroundColor;
	}
	public Color getBackgroundColor(BigInteger index) {
		return backgroundColor;
	}
	public Color getDefaultBackgroundColor() {
		return backgroundColor;
	}
	public void setDefaultBackgroundColor(Color color) {
		this.backgroundColor = color;
	}
}
