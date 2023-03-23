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
package ghidra.app.plugin.core.debug.gui.model;

import ghidra.dbg.target.TargetObject;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.util.HTMLUtilities;

public interface DisplaysObjectValues {
	long getSnap();

	default String getNullDisplay() {
		return "";
	}

	default String getPrimitiveValueDisplay(Object value) {
		assert !(value instanceof TraceObject);
		assert !(value instanceof TraceObjectValue);
		// TODO: Choose decimal or hex for integral types?
		if (value == null) {
			return getNullDisplay();
		}
		return value.toString();
	}

	default String getPrimitiveEdgeType(TraceObjectValue edge) {
		return edge.getTargetSchema().getName() + ":" + edge.getValue().getClass().getSimpleName();
	}

	default String getPrimitiveEdgeToolTip(TraceObjectValue edge) {
		return getPrimitiveValueDisplay(edge.getValue()) + " (" + getPrimitiveEdgeType(edge) + ")";
	}

	default String getObjectLinkDisplay(TraceObjectValue edge) {
		return getObjectDisplay(edge);
	}

	default String getObjectType(TraceObjectValue edge) {
		TraceObject object = edge.getChild();
		return object.getTargetSchema().getName().toString();
	}

	default String getObjectLinkToolTip(TraceObjectValue edge) {
		return "Link to " + getObjectToolTip(edge);
	}

	default String getRawObjectDisplay(TraceObjectValue edge) {
		TraceObject object = edge.getChild();
		if (object.isRoot()) {
			return "<root>";
		}
		return object.getCanonicalPath().toString();
	}

	default String getObjectDisplay(TraceObjectValue edge) {
		TraceObject object = edge.getChild();
		TraceObjectValue displayAttr =
			object.getAttribute(getSnap(), TargetObject.DISPLAY_ATTRIBUTE_NAME);
		if (displayAttr != null) {
			return displayAttr.getValue().toString();
		}
		return getRawObjectDisplay(edge);
	}

	default String getObjectToolTip(TraceObjectValue edge) {
		String display = getObjectDisplay(edge);
		String raw = getRawObjectDisplay(edge);
		if (display.equals(raw)) {
			return display + " (" + getObjectType(edge) + ")";
		}
		return display + " (" + getObjectType(edge) + ":" + raw + ")";
	}

	default String getEdgeDisplay(TraceObjectValue edge) {
		if (edge == null) {
			return "";
		}
		if (edge.isCanonical()) {
			return getObjectDisplay(edge);
		}
		if (edge.isObject()) {
			return getObjectLinkDisplay(edge);
		}
		return getPrimitiveValueDisplay(edge.getValue());
	}

	/**
	 * Get an HTML string representing how the edge's value should be displayed
	 * 
	 * @return the display string
	 */
	default String getEdgeHtmlDisplay(TraceObjectValue edge) {
		if (edge == null) {
			return "";
		}
		if (!edge.isObject()) {
			return "<html>" + HTMLUtilities.escapeHTML(getPrimitiveValueDisplay(edge.getValue()));
		}
		if (edge.isCanonical()) {
			return "<html>" + HTMLUtilities.escapeHTML(getObjectDisplay(edge));
		}
		return "<html><em>" + HTMLUtilities.escapeHTML(getObjectLinkDisplay(edge)) + "</em>";
	}

	default String getEdgeToolTip(TraceObjectValue edge) {
		if (edge == null) {
			return null;
		}
		if (edge.isCanonical()) {
			return getObjectToolTip(edge);
		}
		if (edge.isObject()) {
			return getObjectLinkToolTip(edge);
		}
		return getPrimitiveEdgeToolTip(edge);
	}
}
