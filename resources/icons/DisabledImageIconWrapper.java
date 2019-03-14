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
package resources.icons;

import java.awt.*;
import java.awt.image.ImageObserver;

import javax.accessibility.AccessibleContext;
import javax.swing.ImageIcon;

import resources.ResourceManager;

public class DisabledImageIconWrapper extends ImageIcon implements FileBasedIcon {

    private ImageIcon baseIcon;
    private ImageIcon disabledIcon;
    private Image image;
    private boolean loaded;
    
    /** 
     * The inverse percentage of gray (higher percentage equals less gray) to apply to 
     * the disabled image; higher is brighter.
     */
    int brightnessPercent;

    public DisabledImageIconWrapper( ImageIcon baseIcon ) {
        this( baseIcon, 50 ); // default to half gray
    }
    
    public DisabledImageIconWrapper( ImageIcon baseIcon, int brightnessPercent ) {
        this.baseIcon = baseIcon;
        this.brightnessPercent = brightnessPercent;
    }
    
    public String getFilename() {
    	if ( !(baseIcon instanceof FileBasedIcon) ) {
    		return null;
    	}
    	return ((FileBasedIcon) baseIcon).getFilename();
    }
    
    @Override
    public Image getImage() {
        init();
        return image; 
    }

    @Override
    public AccessibleContext getAccessibleContext() {
        init();
        return disabledIcon.getAccessibleContext();
    }

    @Override
    public String getDescription() {
        init();
        return disabledIcon.getDescription();
    }

    @Override
    public int getIconHeight() {
        init();
        return disabledIcon.getIconHeight();
    }

    @Override
    public int getIconWidth() {
        init();
        return disabledIcon.getIconWidth();
    }

    @Override
    public int getImageLoadStatus() {
        init();
        return disabledIcon.getImageLoadStatus();
    }

    @Override
    public ImageObserver getImageObserver() {
        init();
        return disabledIcon.getImageObserver();
    }

    @Override
    public synchronized void paintIcon(Component c, Graphics g, int x, int y) {
        init();
        super.paintIcon(c, g, x, y);
    }

    @Override
    public void setDescription(String description) {
        init();
        disabledIcon.setDescription(description);
    }

    @Override
    public void setImage(Image image) {
        init();
        this.image = image;
        super.setImage(image);
    }

    @Override
    public String toString() {
        init();
        return disabledIcon.toString(); 
    }

    private synchronized void init() {
        if (!loaded) {
            loaded = true;
            disabledIcon = createImageIcon();
            image = disabledIcon.getImage();
            super.setImage(image);
        }
    }
    
    private ImageIcon createImageIcon() {
        return ResourceManager.createDisabledIcon( baseIcon, brightnessPercent );
    }
}
