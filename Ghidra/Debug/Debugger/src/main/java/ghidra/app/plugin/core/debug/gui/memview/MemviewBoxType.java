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
	INSTRUCTIONS(new GColor("color.debugger.plugin.memview.box.type.instructions")),
	PROCESS(new GColor("color.debugger.plugin.memview.box.type.process")),
	THREAD(new GColor("color.debugger.plugin.memview.box.type.thread")),
	MODULE(new GColor("color.debugger.plugin.memview.box.type.module")),
	REGION(new GColor("color.debugger.plugin.memview.box.type.region")),
	IMAGE(new GColor("color.debugger.plugin.memview.box.type.image")),
	VIRTUAL_ALLOC(new GColor("color.debugger.plugin.memview.box.type.virtual.alloc")),
	HEAP_CREATE(new GColor("color.debugger.plugin.memview.box.type.heap.create")),
	HEAP_ALLOC(new GColor("color.debugger.plugin.memview.box.type.heap.alloc")),
	POOL(new GColor("color.debugger.plugin.memview.box.type.pool")),
	STACK(new GColor("color.debugger.plugin.memview.box.type.stack")),
	PERFINFO(new GColor("color.debugger.plugin.memview.box.type.perfinfo")),
	READ_MEMORY(new GColor("color.debugger.plugin.memview.box.type.read.memory")),
	WRITE_MEMORY(new GColor("color.debugger.plugin.memview.box.type.write.memory")),
	BREAKPOINT(new GColor("color.debugger.plugin.memview.box.type.breakpoint"));

	private final Color color;

	private MemviewBoxType(Color color) {
		this.color = color;
	}

	public Color getColor() {
		return color;
	}
}
