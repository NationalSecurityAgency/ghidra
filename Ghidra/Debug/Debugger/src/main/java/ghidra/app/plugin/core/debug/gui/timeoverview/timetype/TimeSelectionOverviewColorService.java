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

import java.util.*;

import ghidra.trace.model.Lifespan;

public class TimeSelectionOverviewColorService
		extends TimeTypeOverviewColorService {

	@Override
	public String getName() {
		return "Trace Selection";
	}


	@Override
	public void setIndices(TreeSet<Long> set) {
		snapToIndex = new HashMap<>();
		indexToSnap = new HashMap<>();
		if (bounds != null) {
			set.add(bounds.min());
			int splits = overviewComponent.getOverviewPixelCount();
			float span = (float)(bounds.lmax() - bounds.lmin())/splits;
			for (int i = 0; i < splits; i++) {
				long snap = (long)(bounds.lmin() + i*span);
				snapToIndex.put(snap, i);
				indexToSnap.put(i, snap);
			}
		}
	}
	
	@Override
	public Lifespan getBounds() {
		return bounds;
	}

	@Override
	public void setBounds(Lifespan bounds) {
		this.bounds = bounds;
		TreeSet<Long> minset = new TreeSet<>();
		minset.add(bounds.min());
		overviewComponent.setLifeSet(minset);
	}

}
