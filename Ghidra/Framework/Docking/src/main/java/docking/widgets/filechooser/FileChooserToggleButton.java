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
package docking.widgets.filechooser;

import java.awt.Color;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

public class FileChooserToggleButton extends JToggleButton {
	private static final long serialVersionUID = 1L;

    static final Border RAISED_BORDER = BorderFactory.createCompoundBorder(
				BorderFactory.createRaisedBevelBorder(),
				BorderFactory.createEmptyBorder(1,1,1,1));

    static final Border NO_BORDER = new EmptyBorder(RAISED_BORDER.getBorderInsets(new JButton()));

    static final Border LOWERED_BORDER = BorderFactory.createCompoundBorder(
				BorderFactory.createLoweredBevelBorder(),
				BorderFactory.createEmptyBorder(1,1,1,1));

	public FileChooserToggleButton(String text) {
		super(text);
		initBorder();
	}
	
	public FileChooserToggleButton(Action action) {
		super(action);
		initBorder();
	}

	private void initBorder() {
		setForeground(Color.WHITE);
		setOpaque(true);		
		setHorizontalTextPosition(SwingConstants.CENTER);
		setVerticalTextPosition(SwingConstants.BOTTOM);
		clearBorder();		
		
		// prevents the WinXP LNF from painting its awkward borders
		setContentAreaFilled( false );
		
		// changes the border on hover and click
		addMouseListener(new ButtonMouseListener());
		
		// works in conjunction with the mouse listener to properly set the border
		addChangeListener( new ChangeListener() {
            public void stateChanged( ChangeEvent e ) {
                if ( isSelected() ) {
                    setBorder( LOWERED_BORDER );
                }
                else {                    
                    setBorder( NO_BORDER );
                }
            }		    
		} );
		
		setFocusable( false ); // this prevents the focus box from being drawn over the button
	}

	void clearBorder() {
		setBorder(NO_BORDER);
	}

	/** Returns the directory with which this button is associated. */
	File getFile() {
	    return null;
	}

	private class ButtonMouseListener extends MouseAdapter {
		private boolean inside = false;

		private Border defaultBorder;
		
		@Override
        public void mouseEntered(MouseEvent me)  {
		    if ( isSelected() ) {
		        return;
		    }
		    
		    defaultBorder = getBorder();
			setBorder(RAISED_BORDER);
			inside = true;
		}

		@Override
        public void mouseExited(MouseEvent me)  {
		    if ( isSelected() ) {
                return;
            }
		    
			inside = false;
			restoreBorder();
		}

		@Override
        public void mousePressed(MouseEvent e) {
		    if ( isSelected() ) {
                return;
            }
		    
			if (e.getButton() == MouseEvent.BUTTON1) {
				setBorder(LOWERED_BORDER);
			}
		}

		@Override
        public void mouseReleased(MouseEvent e) {
		    if ( isSelected() ) {
                return;
            }
		    
			if (inside) {
				setBorder(RAISED_BORDER);
			}
			else {
				restoreBorder();
			}
		}
		
	    private void restoreBorder() {
	        if ( defaultBorder != null ) {
                setBorder(defaultBorder);
            }           
            else {
                setBorder( NO_BORDER );
            }
	    }
	}	
}
