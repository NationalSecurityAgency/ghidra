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
package ghidra.app.util.headless;

import java.awt.*;
import java.awt.Dialog.ModalExclusionType;
import java.awt.Dialog.ModalityType;
import java.awt.datatransfer.Clipboard;
import java.awt.font.TextAttribute;
import java.awt.im.InputMethodHighlight;
import java.awt.image.*;
import java.net.URL;
import java.util.Map;
import java.util.Properties;

import sun.awt.HeadlessToolkit;

public class MyHeadlessToolkit extends Toolkit {
	
	static volatile boolean swingErrorRegistered = false;
	private static String preferredToolkit;
	
	private Toolkit localToolKit;
	
	static void setup() {
		//System.setProperty("java.awt.headless", "true");
		preferredToolkit = System.getProperty("awt.toolkit", "sun.awt.X11.XToolkit");
		System.setProperty("awt.toolkit", MyHeadlessToolkit.class.getName());
	}
	
	public MyHeadlessToolkit() {
		swingErrorRegistered = true;
		try {
			throw new Exception("Swing invocation detected for Headless Mode");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		getRealToolkit();
	}

	@Override
	public void beep() {
		localToolKit.beep();
	}

	@Override
	public int checkImage(Image image, int width, int height,
			ImageObserver observer) {
		return localToolKit.checkImage(image, width, height, observer);
	}

	@Override
	public Image createImage(String filename) {
		return localToolKit.createImage(filename);
	}

	@Override
	public Image createImage(URL url) {
		return localToolKit.createImage(url);
	}

	@Override
	public Image createImage(ImageProducer producer) {
		return localToolKit.createImage(producer);
	}

	@Override
	public Image createImage(byte[] imagedata, int imageoffset, int imagelength) {
		return localToolKit.createImage(imagedata, imageoffset, imagelength);
	}

	@Override
	public ColorModel getColorModel() throws HeadlessException {
		return localToolKit.getColorModel();
	}

	@Override
	public String[] getFontList() {
		return localToolKit.getFontList();
	}

	@Override
	public FontMetrics getFontMetrics(Font font) {
		return localToolKit.getFontMetrics(font);
	}

	@Override
	public Image getImage(String filename) {
		return localToolKit.getImage(filename);
	}

	@Override
	public Image getImage(URL url) {
		return localToolKit.getImage(url);
	}

	@Override
	public PrintJob getPrintJob(Frame frame, String jobtitle, Properties props) {
		return localToolKit.getPrintJob(frame, jobtitle, props);
	}

	@Override
	public int getScreenResolution() throws HeadlessException {
		return localToolKit.getScreenResolution();
	}

	@Override
	public Dimension getScreenSize() throws HeadlessException {
		return localToolKit.getScreenSize();
	}

	@Override
	public Clipboard getSystemClipboard() throws HeadlessException {
		return localToolKit.getSystemClipboard();
	}

	@Override
	protected EventQueue getSystemEventQueueImpl() {
		return localToolKit.getSystemEventQueue();
	}

	@Override
	public boolean isModalExclusionTypeSupported(
			ModalExclusionType modalExclusionType) {
		return localToolKit.isModalExclusionTypeSupported(modalExclusionType);
	}

	@Override
	public boolean isModalityTypeSupported(ModalityType modalityType) {
		return localToolKit.isModalityTypeSupported(modalityType);
	}

	@Override
	public Map<TextAttribute, ?> mapInputMethodHighlight(
			InputMethodHighlight highlight) throws HeadlessException {
		return localToolKit.mapInputMethodHighlight(highlight);
	}

	@Override
	public boolean prepareImage(Image image, int width, int height,
			ImageObserver observer) {
		return localToolKit.prepareImage(image, width, height, observer);
	}

	@Override
	public void sync() {
		localToolKit.sync();
	}

	private void getRealToolkit() {
		try {
            // We disable the JIT during toolkit initialization.  This
            // tends to touch lots of classes that aren't needed again
            // later and therefore JITing is counter-productiive.
            java.lang.Compiler.disable();
            
			Class<?> cls = null;
            try {
            	try {
                	cls = Class.forName(preferredToolkit);
                } catch (ClassNotFoundException ee) {
                    throw new AWTError("Toolkit not found: " + preferredToolkit);
                }
                if (cls != null) {
                    localToolKit = (Toolkit)cls.newInstance();
                    if (GraphicsEnvironment.isHeadless()) {
                    	localToolKit = new HeadlessToolkit(localToolKit);
                    }
                }
            } catch (InstantiationException e) {
                throw new AWTError("Could not instantiate Toolkit: " + preferredToolkit);
            } catch (IllegalAccessException e) {
                throw new AWTError("Could not access Toolkit: " + preferredToolkit);
            }
            
        } finally {
            // Make sure to always re-enable the JIT.
            java.lang.Compiler.enable();
        }
	}
}
