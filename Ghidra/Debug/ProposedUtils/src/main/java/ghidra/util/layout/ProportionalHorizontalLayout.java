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
package ghidra.util.layout;

import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;

public class ProportionalHorizontalLayout implements LayoutManager2 {
	protected final Map<Component, Double> components = new LinkedHashMap<>();

	public static class Proportion {
		private final double p;

		public Proportion(double p) {
			this.p = p;
		}
	}

	@Override
	public void addLayoutComponent(String name, Component comp) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addLayoutComponent(Component comp, Object constraints) {
		if (!(constraints instanceof Proportion)) {
			throw new IllegalArgumentException();
		}
		Proportion w = (Proportion) constraints;
		components.put(comp, w.p);
	}

	@Override
	public void removeLayoutComponent(Component comp) {
		components.remove(comp);
	}

	@Override
	public Dimension preferredLayoutSize(Container parent) {
		double totalP = components.values().stream().reduce(0.0, Double::sum);
		Dimension result = new Dimension();
		for (Map.Entry<Component, Double> ent : components.entrySet()) {
			double fraction = ent.getValue() / totalP;
			if (fraction == 0) {
				continue;
			}
			Dimension size = ent.getKey().getPreferredSize();
			// Request enough such that the everyone will get at least its preferred size
			result.width = Math.max(result.width, (int) Math.ceil(size.width / fraction));
			result.height = Math.max(result.height, size.height);
		}
		return result;
	}

	@Override
	public Dimension minimumLayoutSize(Container parent) {
		double totalP = components.values().stream().reduce(0.0, Double::sum);
		Dimension result = new Dimension();
		for (Map.Entry<Component, Double> ent : components.entrySet()) {
			double fraction = ent.getValue() / totalP;
			if (fraction == 0) {
				continue;
			}
			Dimension size = ent.getKey().getMinimumSize();
			// Request enough such that the everyone will get at least its preferred size
			result.width = Math.max(result.width, (int) Math.ceil(size.width / fraction));
			result.height = Math.max(result.height, size.height);
		}
		return result;
	}

	@Override
	public Dimension maximumLayoutSize(Container target) {
		return new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE);
	}

	@Override
	public float getLayoutAlignmentX(Container target) {
		return 0.5f;
	}

	@Override
	public float getLayoutAlignmentY(Container target) {
		return 0.5f;
	}

	@Override
	public void layoutContainer(Container parent) {
		Dimension pDim = parent.getSize();
		double totalWeight = components.values().stream().reduce(0.0, Double::sum);
		double running = 0;
		Rectangle cur = new Rectangle();
		cur.x = 0;
		cur.y = 0;
		cur.height = pDim.height;
		for (Map.Entry<Component, Double> ent : components.entrySet()) {
			double w = ent.getValue();
			running += w;
			int newX = (int) (pDim.width * running / totalWeight);
			cur.width = newX - cur.x;
			ent.getKey().setBounds(cur);
			cur.x = newX;
		}
	}

	@Override
	public void invalidateLayout(Container target) {
		// No cache to clear
	}
}
