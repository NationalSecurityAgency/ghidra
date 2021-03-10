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
package docking;

import java.awt.Component;
import java.awt.Point;
import java.awt.event.MouseEvent;
import java.util.Objects;

/**
 * A class that holds information used to show a popup menu 
 */
public class PopupMenuContext {

	private Component component;
	private MouseEvent event;
	private Point point;

	PopupMenuContext(MouseEvent event) {
		this.event = event;
		this.component = Objects.requireNonNull(event.getComponent());
		this.point = event.getPoint();
	}

	PopupMenuContext(Component component, Point point) {
		this.component = Objects.requireNonNull(component);
		this.point = point;
	}

	public MouseEvent getEvent() {
		return event;
	}

	public Component getComponent() {
		return component;
	}

	public Point getPoint() {
		return new Point(point);
	}

	public Object getSource() {
		if (event != null) {
			return event.getSource();
		}
		return component;
	}
}
