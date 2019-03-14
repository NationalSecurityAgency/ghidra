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
package docking;

import java.awt.Point;
import java.awt.Window;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import generic.test.AbstractGTest;
import generic.test.AbstractGenericTest;

/**
 * This class mainly serves as a conduit through which testing code can access some of the 
 * non-public internals of {@link DockingWindowManager}, without opening up its interface to the
 * public <b>and</b> without using reflective magic.
 */
public class DockingWindowManagerTestUtils {

	public static Set<ComponentProvider> getActiveProviders(final DockingWindowManager dwm) {
		PlaceholderManager pm = dwm.getPlaceholderManager();
		return pm.getActiveProviders();
	}

	/**
	 * Moves the given provider to its own window, at its current location. 
	 * 
	 * @param provider the provider to move
	 * @return the provider's window
	 */
	public static Window moveProviderToWindow(final DockingWindowManager dwm,
			final ComponentProvider provider) {

		AbstractGenericTest.runSwing(() -> {
			if (!dwm.containsProvider(provider)) {
				return;
			}

			ComponentPlaceholder placeholder = dwm.getActivePlaceholder(provider);
			DockableComponent dockingComponent = dwm.getDockableComponent(provider);
			Point point = new Point(0, 0);
			if (dockingComponent.isShowing()) {
				point = dockingComponent.getLocationOnScreen();
			}
			dwm.movePlaceholder(placeholder, point);
		});

		Window w = AbstractGTest.waitForValue(() -> dwm.getProviderWindow(provider));
		return w;
	}

	public static void moveProvider(final DockingWindowManager dwm, final ComponentProvider movee,
			final ComponentProvider relativeTo, final WindowPosition position) {

		AbstractGenericTest.runSwing(() -> {
			ComponentPlaceholder moveePlaceholder = dwm.getPlaceholder(movee);
			ComponentPlaceholder relativeToPlaceholder = dwm.getPlaceholder(relativeTo);
			dwm.movePlaceholder(moveePlaceholder, relativeToPlaceholder, position);
		});
	}

	public static DockableComponent getDockableComponent(final DockingWindowManager dwm,
			final ComponentProvider provider) {

		final AtomicReference<DockableComponent> ref = new AtomicReference<>();
		AbstractGenericTest.runSwing(() -> ref.set(dwm.getDockableComponent(provider)));

		return ref.get();
	}
}
