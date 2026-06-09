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
package ghidra.app.plugin.core.debug.gui.timeoverview.timetype;

import java.awt.Color;

import generic.theme.GColor;

/**
 * An enum for the different types that are represented by unique colors by the
 * {@link TimeTypeOverviewColorService}
 */
public enum TimeType {
	THREAD_ADDED("+T", new GColor("color.debugger.plugin.timeoverview.box.type.thread.added")),
	THREAD_REMOVED("-T", new GColor("color.debugger.plugin.timeoverview.box.type.thread.removed")),
	THREAD_CHANGED("*T", new GColor("color.debugger.plugin.timeoverview.box.type.thread.changed")),
	MODULE_ADDED("+M", new GColor("color.debugger.plugin.timeoverview.box.type.module.added")),
	MODULE_REMOVED("-M", new GColor("color.debugger.plugin.timeoverview.box.type.module.removed")),
	MODULE_CHANGED("*M", new GColor("color.debugger.plugin.timeoverview.box.type.module.changed")),
	REGION_ADDED("+R", new GColor("color.debugger.plugin.timeoverview.box.type.region.added")),
	REGION_REMOVED("-R", new GColor("color.debugger.plugin.timeoverview.box.type.region.removed")),
	REGION_CHANGED("*R", new GColor("color.debugger.plugin.timeoverview.box.type.region.changed")),
	BPT_ADDED("+B", new GColor("color.debugger.plugin.timeoverview.box.type.breakpoint.added")),
	BPT_REMOVED("-B", new GColor("color.debugger.plugin.timeoverview.box.type.breakpoint.removed")),
	BPT_CHANGED("*B", new GColor("color.debugger.plugin.timeoverview.box.type.breakpoint.changed")),
	BPT_HIT(">B", new GColor("color.debugger.plugin.timeoverview.box.type.breakpoint.hit")),
	BOOKMARK_ADDED("+MK", new GColor("color.debugger.plugin.timeoverview.box.type.bookmark.added")),
	BOOKMARK_REMOVED("-MK", new GColor("color.debugger.plugin.timeoverview.box.type.bookmark.removed")),
	BOOKMARK_CHANGED("*MK", new GColor("color.debugger.plugin.timeoverview.box.type.bookmark.changed")),
	UNDEFINED("", new GColor("color.debugger.plugin.timeoverview.box.type.undefined"));

	final private String description;
	final private Color color;

	TimeType(String description, Color color) {
		this.description = description;
		this.color = color;
	}

	/**
	 * Returns a description of this enum value.
	 * 
	 * @return a description of this enum value.
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Returns a color of this enum value.
	 * 
	 * @return a color of this enum value.
	 */
	public Color getDefaultColor() {
		return color;
	}

}
