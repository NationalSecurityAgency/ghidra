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
package ghidra.app.plugin.core.debug.gui.objects.components;

import java.util.List;

import javax.swing.JComponent;

import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.dbg.target.TargetObject;

public interface ObjectPane {

	public ObjectContainer getContainer();

	public TargetObject getTargetObject();

	public TargetObject getSelectedObject();

	public JComponent getComponent();

	public JComponent getPrincipalComponent();

	public List<? extends Object> update(ObjectContainer container);

	public void signalDataChanged(ObjectContainer container);

	public void signalContentsChanged(ObjectContainer container);

	public void signalUpdate(ObjectContainer container);

	public String getName();

	public void setFocus(TargetObject object, TargetObject focused);

	public void setRoot(ObjectContainer root, TargetObject targetObject);

}
