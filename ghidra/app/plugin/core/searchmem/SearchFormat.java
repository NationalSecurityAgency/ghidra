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
package ghidra.app.plugin.core.searchmem;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.event.ChangeListener;

public abstract class SearchFormat {
	private String name;
	protected boolean isBigEndian;
	protected ChangeListener changeListener;
	
	protected SearchFormat(String name, ChangeListener listener) {
		this.name = name;
		this.changeListener = listener;
	}
	public String getName() {
		return name;
	}
	
	public JPanel getOptionsPanel() {
		JPanel noOptionsPanel = new JPanel();
        noOptionsPanel.setBorder(BorderFactory.createTitledBorder("Format Options"));
        return noOptionsPanel;
	}
		
	public void setEndieness(boolean isBigEndian) {
		this.isBigEndian = isBigEndian;
	}
	public boolean usesEndieness() {
		return true;
	}
	public boolean supportsBackwardsSearch() {
		return true;
	}
	
	public abstract String getToolTip();

	public abstract SearchData getSearchData( String input );
	
	
}
