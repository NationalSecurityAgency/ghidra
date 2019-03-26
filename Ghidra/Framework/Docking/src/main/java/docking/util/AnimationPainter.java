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

import ghidra.util.bean.GGlassPane;

import java.awt.Graphics;

/**
 * An interface used with {@link AnimationUtils} to allow clients to use the timing 
 * framework while performing their own painting.
 */
public interface AnimationPainter {

	/**
	 * Called back each time the animation system generates a timing event. 
	 * 
	 * @param glassPane the glass pane upon which painting takes place
	 * @param graphics the graphics used to paint
	 * @param percentComplete a value from 0 to 1, 1 being fully complete.
	 */
	public void paint(GGlassPane glassPane, Graphics graphics, double percentComplete);
}
