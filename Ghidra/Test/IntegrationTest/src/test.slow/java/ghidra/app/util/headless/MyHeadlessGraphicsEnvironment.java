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
package ghidra.app.util.headless;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.Locale;

import sun.java2d.HeadlessGraphicsEnvironment;

public class MyHeadlessGraphicsEnvironment extends GraphicsEnvironment {

	static volatile boolean swingErrorRegistered = false;
	private static String preferredGraphicsEnv;
	
	private GraphicsEnvironment localEnv;
	
	static void setup() {
		//System.setProperty("java.awt.headless", "true");
		preferredGraphicsEnv = System.getProperty("java.awt.graphicsenv");
		System.setProperty("java.awt.graphicsenv", MyHeadlessGraphicsEnvironment.class.getName());
	}
	
	public MyHeadlessGraphicsEnvironment() {
		swingErrorRegistered = true;
		try {
			throw new Exception("Swing invocation detected for Headless Mode");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		getRealGraphicsEnvironemnt();
	}

	@Override
	public Graphics2D createGraphics(BufferedImage img) {
		return null;
	}

	@Override
	public Font[] getAllFonts() {
		return localEnv.getAllFonts();
	}

	@Override
	public String[] getAvailableFontFamilyNames() {
		return localEnv.getAvailableFontFamilyNames();
	}

	@Override
	public String[] getAvailableFontFamilyNames(Locale l) {
		return localEnv.getAvailableFontFamilyNames(l);
	}

	@Override
	public GraphicsDevice getDefaultScreenDevice() throws HeadlessException {
		return localEnv.getDefaultScreenDevice();
	}

	@Override
	public GraphicsDevice[] getScreenDevices() throws HeadlessException {
		return localEnv.getScreenDevices();
	}
	
	private void getRealGraphicsEnvironemnt() {
		try {
			localEnv = (GraphicsEnvironment) Class.forName(preferredGraphicsEnv).newInstance();
			if (isHeadless()) {
				localEnv = new HeadlessGraphicsEnvironment(localEnv);
			}
		} catch (ClassNotFoundException e) {
			throw new Error("Could not find class: " + preferredGraphicsEnv);
		} catch (InstantiationException e) {
			throw new Error("Could not instantiate Graphics Environment: " + preferredGraphicsEnv);
		} catch (IllegalAccessException e) {
			throw new Error("Could not access Graphics Environment: " + preferredGraphicsEnv);
		}
	}

}
