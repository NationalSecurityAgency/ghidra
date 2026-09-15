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
package ghidra.app.plugin.core.flowarrow;

import java.awt.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.RefType;

class DefaultFlowArrow extends FlowArrow {

	private static final Stroke NORMAL_STROKE = new BasicStroke(1, BasicStroke.CAP_SQUARE,
		BasicStroke.JOIN_MITER);
	private static final Stroke NORMAL_ACTIVE_STROKE = new BasicStroke(2, BasicStroke.CAP_SQUARE,
		BasicStroke.JOIN_MITER);

	DefaultFlowArrow(FlowArrowMarginProvider provider, Component canvas, Address start, Address end,
			RefType referenceType) {
		super(provider, canvas, start, end, referenceType);
	}

	@Override
	Stroke getSelectedStroke() {
		return NORMAL_ACTIVE_STROKE;
	}

	@Override
	Stroke getActiveStroke() {
		return NORMAL_ACTIVE_STROKE;
	}

	@Override
	Stroke getInactiveStroke() {
		return NORMAL_STROKE;
	}
}
