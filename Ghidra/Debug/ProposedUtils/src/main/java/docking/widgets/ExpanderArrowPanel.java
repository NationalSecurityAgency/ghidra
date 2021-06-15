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
package docking.widgets;

import java.awt.*;
import java.awt.event.*;
import java.util.concurrent.CompletableFuture;

import javax.swing.JPanel;

import ghidra.util.datastruct.ListenerSet;

public class ExpanderArrowPanel extends JPanel {
	// TODO: Can I make this consistent with the UI LaF
	protected final static Polygon ARROW =
		new Polygon(new int[] { 5, -5, -5 }, new int[] { 0, -5, 5 }, 3);
	protected final static Dimension SIZE = new Dimension(16, 16);
	protected final static int ANIM_MILLIS = 80;
	protected final static int FRAME_MILLIS = 30; // Approx 30 fps

	private final ListenerSet<ExpanderArrowExpansionListener> listeners =
		new ListenerSet<>(ExpanderArrowExpansionListener.class);

	private boolean expanded = false;

	private double animTheta;
	private boolean animActive = false;
	private long animTimeEnd;
	private double animThetaEnd;
	private double animThetaOverTimeRate;

	private final MouseListener mouseListener = new MouseAdapter() {
		@Override
		public void mouseClicked(MouseEvent e) {
			toggle();
		}
	};

	{
		addMouseListener(mouseListener);
	}

	public void addExpansionListener(ExpanderArrowExpansionListener listener) {
		listeners.add(listener);
	}

	public void removeExpansionListener(ExpanderArrowExpansionListener listener) {
		listeners.remove(listener);
	}

	protected synchronized void animateTheta(double destTheta) {
		animTimeEnd = System.currentTimeMillis() + ANIM_MILLIS;
		animThetaEnd = destTheta;
		animThetaOverTimeRate = (destTheta - animTheta) / ANIM_MILLIS;
		animActive = true;
		scheduleNextFrame();
	}

	public void toggle() {
		setExpanded(!expanded);
	}

	protected boolean fireChanging(boolean newExpanded) {
		try {
			listeners.fire.changing(newExpanded);
		}
		catch (ExpanderArrowExpansionVetoException e) {
			return false;
		}
		return true;
	}

	protected void fireChanged() {
		listeners.fire.changed(expanded);
	}

	public void setExpanded(boolean expanded) {
		if (this.expanded == expanded) {
			return;
		}
		if (!fireChanging(expanded)) {
			return;
		}
		double destTheta = expanded ? Math.PI / 2 : 0;
		animateTheta(destTheta);
		this.expanded = expanded;
		fireChanged();
	}

	public boolean isExpanded() {
		return expanded;
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		Graphics2D g2 = (Graphics2D) g.create();
		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
		g2.translate((double) SIZE.width / 2, (double) SIZE.height / 2);
		g2.rotate(animTheta);
		g2.fillPolygon(ARROW);

		if (!animActive) {
			return;
		}
		long time = System.currentTimeMillis();
		double timeDiff = Math.max(0, animTimeEnd - time);
		if (timeDiff != 0) {
			double thetaDiff = timeDiff * animThetaOverTimeRate;
			animTheta = animThetaEnd - thetaDiff;
			scheduleNextFrame();
			return;
		}
		animActive = false;
		if (animTheta != animThetaEnd) {
			animTheta = animThetaEnd;
			scheduleNextFrame();
		}
	}

	@Override
	public Dimension getPreferredSize() {
		return SIZE;
	}

	@Override
	public Dimension getMinimumSize() {
		return SIZE;
	}

	protected void scheduleNextFrame() {
		CompletableFuture.runAsync(() -> {
			try {
				Thread.sleep(FRAME_MILLIS);
			}
			catch (InterruptedException e) {
				// Whatever. Render early.
			}
			repaint();
		});
	}
}
