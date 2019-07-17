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
package ghidra.graph.support;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.JComponent;

import org.apache.commons.collections4.Factory;
import org.apache.commons.collections4.map.LazyMap;

import docking.widgets.label.GDHtmlLabel;
import ghidra.graph.graphs.AbstractTestVertex;
import ghidra.graph.graphs.TestEdge;
import ghidra.graph.viewer.event.mouse.VertexTooltipProvider;

public class TestVertexTooltipProvider
		implements VertexTooltipProvider<AbstractTestVertex, TestEdge> {

	private AtomicBoolean tooltipTriggered = new AtomicBoolean();
	private Map<AbstractTestVertex, List<SpyTooltip>> shownTooltipsByVertex =
		LazyMap.lazyMap(new HashMap<>(), (Factory<List<SpyTooltip>>) () -> new ArrayList<>());

	@Override
	public JComponent getTooltip(AbstractTestVertex v) {
		String name = v.getName();
		String text = "This is a tooltip for " + name;
		SpyTooltipLabel spy = new SpyTooltipLabel(text);
		shownTooltipsByVertex.get(v).add(spy);
		tooltipTriggered.set(true);
		return spy;
	}

	@Override
	public JComponent getTooltip(AbstractTestVertex v, TestEdge e) {
		String name = v.getName();
		String text = "This is a tooltip for " + name + " and edge " + e;
		SpyTooltipLabel spy = new SpyTooltipLabel(text);
		shownTooltipsByVertex.get(v).add(spy);
		tooltipTriggered.set(true);
		return spy;
	}

	@Override
	public String getTooltipText(AbstractTestVertex v, MouseEvent e) {

		String name = v.getName();
		String text = "This is a tooltip string for " + name + " @ " + new Date();
		SpyTooltipText spy = new SpyTooltipText(text);
		shownTooltipsByVertex.get(v).add(spy);
		tooltipTriggered.set(true);
		return text;
	}

	public List<SpyTooltip> getShownTooltips(AbstractTestVertex v) {
		return Collections.unmodifiableList(shownTooltipsByVertex.get(v));
	}

	public boolean isTooltipTriggered() {
		return tooltipTriggered.get();
	}

	public void clearTooltipTriggered() {
		tooltipTriggered.set(false);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	public interface SpyTooltip {
		// shared hierarchy interface
		public String getTooltipAsText();
	}

	public class SpyTooltipText implements SpyTooltip {

		private String text;

		SpyTooltipText(String text) {
			this.text = text;
		}

		@Override
		public String getTooltipAsText() {
			return text;
		}

	}

	public class SpyTooltipLabel extends GDHtmlLabel implements SpyTooltip {

		SpyTooltipLabel(String text) {
			setText(text);
			setOpaque(true);
			setBackground(Color.ORANGE.darker());
			setPreferredSize(new Dimension(200, 100));
		}

		@Override
		public String getTooltipAsText() {
			return getText();
		}
	}
}
