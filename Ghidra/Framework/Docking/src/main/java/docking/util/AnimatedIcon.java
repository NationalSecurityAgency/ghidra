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
package docking.util;

import java.awt.Component;
import java.awt.Graphics;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

import javax.swing.Icon;
import javax.swing.Timer;

public class AnimatedIcon implements Icon {

	/** best guess at how many timer invocations may happen before paint gets called*/
	private static final int MAGIC_TIMER_CALLS_WITHOUT_PAINT_CALL = 5;

	private final List<? extends Icon> iconList;
	private int currentIconIndex = 0;
	private Component component;
	private int height;
	private int width;
	private int skipFrames;
	private int skipFrameCount = 0;
	private Timer timer;
	private int paintCounter = 0;

	public AnimatedIcon(List<? extends Icon> icons, int frameDelay, int framesToSkip) {
		this.iconList = icons;
		this.skipFrames = framesToSkip;
		timer = new Timer(frameDelay, new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (--paintCounter <= 0) {
					timer.stop();
					return;
				}

				if (skipFrameCount > 0) {
					skipFrameCount--;
					return;
				}
				if (++currentIconIndex >= iconList.size()) {
					currentIconIndex = 0;
					skipFrameCount = skipFrames;
				}
				if (component != null) {
					component.repaint();
				}
			}
		});

		for (Icon icon : iconList) {
			width = Math.max(width, icon.getIconWidth());
			height = Math.max(height, icon.getIconHeight());
		}
	}

	@Override
	public int getIconHeight() {
		return height;
	}

	@Override
	public int getIconWidth() {
		return width;
	}

	private void restartAnimation() {
		timer.start();
		paintCounter = MAGIC_TIMER_CALLS_WITHOUT_PAINT_CALL;
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		restartAnimation();
		iconList.get(currentIconIndex).paintIcon(c, g, x, y);
		component = c;
	}

}
