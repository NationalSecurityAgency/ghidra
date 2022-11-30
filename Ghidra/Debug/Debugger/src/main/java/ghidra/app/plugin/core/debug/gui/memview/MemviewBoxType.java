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

import generic.theme.GColor;

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
		new GColor("color.debugger.plugin.memview.box.type.instructions"),
		new GColor("color.debugger.plugin.memview.box.type.process"),
		new GColor("color.debugger.plugin.memview.box.type.thread"),
		new GColor("color.debugger.plugin.memview.box.type.module"),
		new GColor("color.debugger.plugin.memview.box.type.region"),
		new GColor("color.debugger.plugin.memview.box.type.image"),
		new GColor("color.debugger.plugin.memview.box.type.virtual.alloc"),
		new GColor("color.debugger.plugin.memview.box.type.heap.create"),
		new GColor("color.debugger.plugin.memview.box.type.heap.alloc"),
		new GColor("color.debugger.plugin.memview.box.type.pool"),
		new GColor("color.debugger.plugin.memview.box.type.stack"),
		new GColor("color.debugger.plugin.memview.box.type.perfinfo"),
		new GColor("color.debugger.plugin.memview.box.type.read.memory"),
		new GColor("color.debugger.plugin.memview.box.type.write.memory"),
		new GColor("color.debugger.plugin.memview.box.type.breakpoint"),
	};

	public Color getColor() {
		return colors[this.ordinal()];
	}

	public void setColor(Color color) {
		colors[this.ordinal()] = color;
	}
}
