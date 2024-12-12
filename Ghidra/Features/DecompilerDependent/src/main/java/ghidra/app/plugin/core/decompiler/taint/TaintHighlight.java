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
package ghidra.app.plugin.core.decompiler.taint;

import java.awt.Color;

import generic.theme.GColor;

public enum TaintHighlight {

	SINK("SINK", -3, new GColor("color.bg.decompiler.highlights.sink")),
	SOURCE("SOURCE", -2, new GColor("color.bg.decompiler.highlights.source")),
	SINKSOURCE("SINK, SOURCE", -1, new GColor("color.bg.decompiler.highlights.sinksource")),
	SOURCESINK("SOURCE, SINK", -1, new GColor("color.bg.decompiler.highlights.sinksource")),
	OTHER("0", 0, new GColor("color.bg.decompiler.highlights.path"));

	private final String tag;
	private final int priority;
	private final Color color;

	private TaintHighlight(String tag, int priority, Color color) {
		this.tag = tag;
		this.priority = priority;
		this.color = color;
	}

	public String getTag() {
		return tag;
	}

	public int getPriority() {
		return priority;
	}

	public Color getColor() {
		return color;
	}

	public static TaintHighlight byLabel(String label) {
		for (TaintHighlight v : TaintHighlight.values()) {
			if (v.getTag().equals(label)) {
				return v;
			}
		}
		return OTHER;
	}
}
