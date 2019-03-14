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
package ghidra.app.plugin.core.function.tags;

import java.awt.Color;
import java.awt.Component;
import java.awt.event.MouseEvent;

import javax.swing.*;

import ghidra.program.model.listing.FunctionTag;

/**
 * Simple list for displaying {@link FunctionTag} items. The only part of the tag 
 * displayed in the list is the name attribute.
 */
public class FunctionTagList extends JList<FunctionTag> {

	public FunctionTagList(DefaultListModel<FunctionTag> model) {
		super(model);
		setCellRenderer(getCellRenderer());
	}

	@Override
	public String getToolTipText(MouseEvent evt) {
		int index = locationToIndex(evt.getPoint());
		if (index == -1 || index >= getModel().getSize()) {
			return "";
		}
		Object obj = getModel().getElementAt(index);
		if (obj instanceof FunctionTag) {
			FunctionTag tag = (FunctionTag) obj;

			if (tag.getComment().isEmpty()) {
				return "<no comment set>";
			}

			return tag.getComment();
		}

		return "";
	}

	/**
	 * Custom renderer for this list ensures that we only show the name attribute of
	 * each {@link FunctionTag} object in the list.
	 * 
	 * @return the cell renderer
	 */
	@Override
	public ListCellRenderer<? super FunctionTag> getCellRenderer() {
		return new DefaultListCellRenderer() {
			@Override
			public Component getListCellRendererComponent(JList<?> list, Object value, int index,
					boolean isSelected, boolean cellHasFocus) {
				FunctionTag tag = (FunctionTag) value;
				Component listCellRendererComponent = super.getListCellRendererComponent(list,
					tag.getName(), index, isSelected, cellHasFocus);

				// If this tag is a temporary one (ie: read-in from a file), then it is
				// read-only and should be indicated to the user as a different color.
				if (value instanceof FunctionTagTemp) {
					if (cellHasFocus) {
						listCellRendererComponent.setForeground(Color.white);
					}
					else {
						listCellRendererComponent.setForeground(Color.blue);
					}
				}
				return listCellRendererComponent;
			}
		};
	}
}
