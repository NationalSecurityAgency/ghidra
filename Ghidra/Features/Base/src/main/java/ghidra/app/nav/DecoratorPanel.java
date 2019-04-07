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
package ghidra.app.nav;

import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.*;

public class DecoratorPanel extends JPanel {
    
	public DecoratorPanel(JComponent component, boolean isConnected) {
		setLayout(new BorderLayout());
		add(component);
		setConnnected( isConnected );
	}
	
	public void setConnnected( boolean isConnected ) {
		if ( !isConnected ) {
			setBorder( BorderFactory.createLineBorder( Color.ORANGE, 2 ) );
		}
		else {
			setBorder( BorderFactory.createEmptyBorder() );
		}
	}

//	public void setNorthPanel(JComponent comp) {
//		add(comp, BorderLayout.NORTH);
//	}
}
