/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import resources.ResourceManager;

public class AnimatedIcon implements Icon {

    /** best guess at how many timer invocations may happen before paint gets called*/
    private static final int MAGIC_TIMER_CALLS_WITHOUT_PAINT_CALL = 5;
    
	private final List<Icon> iconList;
	private int currentIconIndex = 0;
	private Component component;
	private int height;
	private int width;
	private int skipFrames;
	private int skipFrameCount = 0;
    private Timer timer;
    private int paintCounter = 0;
    
	public AnimatedIcon(List<Icon> icons, int frameDelay, int framesToSkip) {
		this.iconList = icons;
		this.skipFrames = framesToSkip;
		timer = new Timer(frameDelay, new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			    if ( --paintCounter <= 0 ) {
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
		
		for ( Icon icon : iconList ) {
			width = Math.max(width, icon.getIconWidth());
			height = Math.max(height, icon.getIconHeight());
		}
	}

	public int getIconHeight() {
		return height;
	}

	public int getIconWidth() {
		return width;
	}

	private void restartAnimation() {
	    timer.start();
	    paintCounter = MAGIC_TIMER_CALLS_WITHOUT_PAINT_CALL;
	}
	
	public void paintIcon(Component c, Graphics g, int x, int y) {
	    restartAnimation();
		iconList.get(currentIconIndex).paintIcon( c, g, x, y );
		component = c;
	}
	
	public static void main(String[] args) {
		JFrame frame = new JFrame("Test");
		List<Icon> iconList = new ArrayList<Icon>();
		iconList.add(ResourceManager.loadImage( "images/weather-clear.png" ));
		iconList.add(ResourceManager.loadImage( "images/weather-few-clouds-reverse.png" ));
		iconList.add(ResourceManager.loadImage( "images/weather-overcast.png" ));
		iconList.add(ResourceManager.loadImage( "images/weather-showers.png" ));
		iconList.add(ResourceManager.loadImage( "images/weather-few-clouds.png" ));
		iconList.add(ResourceManager.loadImage( "images/weather-clear.png" ));
		AnimatedIcon icon = new AnimatedIcon(iconList, 400, 0);
		JLabel label = new JLabel(icon);
		frame.getContentPane().add( label );
		frame.setVisible( true );
	}
}
