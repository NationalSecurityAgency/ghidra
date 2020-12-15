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
package ghidra.app.plugin.core.debug.gui.memview;

import java.awt.Color;

public enum MemviewBoxType {
	INSTRUCTIONS,
	PROCESS,
	THREAD,
	MODULE,
	REGION,
	IMAGE,
	VIRTUAL_ALLOC,
	HEAP_CREATE,
	HEAP_ALLOC,
	POOL,
	STACK,
	PERFINFO,
	READ_MEMORY,
	WRITE_MEMORY,
	BREAKPOINT;

	Color[] colors = { //
		new Color(128, 000, 000), // INSTRUCTIONS
		new Color(200, 200, 255), // PROCESS
		new Color(200, 255, 255), // THREAD
		Color.GREEN, //new Color(000, 150, 200), // MODULE
		Color.YELLOW, //new Color(000, 150, 200), // REGION
		Color.MAGENTA, //new Color(050, 100, 255), // IMAGE
		Color.LIGHT_GRAY, // VIRTUAL_ALLOC
		Color.BLUE, // HEAP_CREATE
		new Color(000, 100, 050), // HEAP_ALLOC
		new Color(100, 000, 150), // POOL
		Color.CYAN, // STACK
		Color.LIGHT_GRAY, // PERFINFO
		Color.DARK_GRAY, // READ_MEMORY
		Color.BLUE,  // WRITE_MEMORY
		Color.RED,  // WRITE_MEMORY
	};

	public Color getColor() {
		return colors[this.ordinal()];
	}

	public void setColor(Color color) {
		colors[this.ordinal()] = color;
	}
}
