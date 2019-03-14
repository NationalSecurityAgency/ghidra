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
package ghidra.app.plugin.core.overview.entropy;

import java.awt.Color;
import java.util.ArrayList;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

/**
 * Manages the colors used by the entropy overview bar.
 */
public class Palette {
	private Color uninitializedColor;
	private Color[] colors;
	private ArrayList<KnotRecord> knots;

	private WeakSet<ChangeListener> listeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

	public Palette(int sz, Color uninit) {
		uninitializedColor = uninit;
		colors = new Color[sz];
		knots = new ArrayList<>();
	}

	void addPaletteListener(ChangeListener listener) {
		listeners.add(listener);
	}

	private void firePaletteChanged() {
		ChangeEvent changeEvent = new ChangeEvent(this);
		for (ChangeListener listener : listeners) {
			listener.stateChanged(changeEvent);
		}
	}

	public int getSize() {
		if (colors == null) {
			return 0;
		}
		return colors.length;
	}

	public Color getColor(int i) {
		if (i < 0) {
			return uninitializedColor;
		}
		return colors[i];
	}

	public void setBase(Color lo, Color hi) {
		double step = 1.0 / (colors.length - 1);
		double t = 0.00001;

		for (int i = 0; i < colors.length; ++i) {
			int red = (int) (lo.getRed() * (1.0 - t) + hi.getRed() * t);
			int green = (int) (lo.getGreen() * (1.0 - t) + hi.getGreen() * t);
			int blue = (int) (lo.getBlue() * (1.0 - t) + hi.getGreen() * t);
			t += step;
			colors[i] = new Color(red, green, blue);
		}
		knots.clear();
		firePaletteChanged();
	}

	public ArrayList<KnotRecord> getKnots() {
		return knots;
	}

	public void addKnot(String name, Color knot, int start, int point) {
		int bound = 2 * (point - start) + 1 + start;
		if (bound > colors.length) {
			bound = colors.length;
		}
		KnotRecord newrec = new KnotRecord(name, knot, start, bound, point);
		knots.add(newrec);
		mergeKnot(newrec);

		firePaletteChanged();
	}

	private void mergeKnot(KnotRecord k) {
		int start = k.start;
		double radianstep = Math.toRadians(180) / (k.point - k.start);
		double cur = 0.0;
		while (start < k.end) {
			Color oldcolor = colors[start];
			Color knot = k.color;
			double t = (-Math.cos(cur) + 1.0) / 2.0;
			double tmp = (knot.getRed() - oldcolor.getRed()) * t + oldcolor.getRed();
			int red = (int) Math.floor(tmp);
			tmp = (knot.getGreen() - oldcolor.getGreen()) * t + oldcolor.getGreen();
			int green = (int) Math.floor(tmp);
			tmp = (knot.getBlue() - oldcolor.getBlue()) * t + oldcolor.getBlue();
			int blue = (int) Math.floor(tmp);
			colors[start] = new Color(red, green, blue);
			cur += radianstep;
			start += 1;
		}
	}
}
