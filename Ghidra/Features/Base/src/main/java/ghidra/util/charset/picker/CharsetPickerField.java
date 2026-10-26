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
package ghidra.util.charset.picker;

import java.awt.BorderLayout;
import java.awt.ItemSelectable;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import javax.swing.*;

import docking.widgets.button.BrowseButton;
import generic.theme.GIcon;
import ghidra.util.HTMLUtilities;
import ghidra.util.charset.CharsetInfo;
import ghidra.util.charset.CharsetInfoManager;
import ghidra.util.datastruct.ListenerSet;

/**
 * A swing component that displays the name of a charset in a text field and allows the user to
 * pick a new one using a popup dialog.
 */
public class CharsetPickerField extends JPanel implements ItemSelectable {
	private JTextField charsetTF;
	private BrowseButton browseButton;
	private JButton clearButton;
	private Icon clearIcon = new GIcon("icon.text.field.clear");

	private CharsetInfo csi;
	private ListenerSet<ItemListener> listeners = new ListenerSet<>(ItemListener.class, false);

	public CharsetPickerField() {
		this((CharsetInfo) null);
	}

	public CharsetPickerField(String charsetName) {
		this(CharsetInfoManager.getInstance().get(charsetName, StandardCharsets.US_ASCII));
	}

	public CharsetPickerField(CharsetInfo csi) {
		super(new BorderLayout());

		this.charsetTF = new JTextField(15);
		this.charsetTF.setEditable(false);
		this.charsetTF.setFocusable(false);
		this.charsetTF.getAccessibleContext().setAccessibleName("Charset Name");

		JPanel buttonPanel = new JPanel(new BorderLayout(1, 0));
		
		this.clearButton = new JButton(clearIcon);
		this.clearButton.addActionListener(_ -> clearCharset());
		this.clearButton.getAccessibleContext().setAccessibleName("Clear Selected Charset");
		this.clearButton.setToolTipText("Clear Charset");

		this.browseButton = new BrowseButton();
		this.browseButton.addActionListener(_ -> chooseCharset());
		this.browseButton.getAccessibleContext().setAccessibleName("Browse Charsets");
		this.browseButton.setToolTipText("Browse Charsets");
		

		buttonPanel.add(clearButton, BorderLayout.WEST);
		buttonPanel.add(browseButton, BorderLayout.EAST);

		add(charsetTF, BorderLayout.CENTER);
		add(buttonPanel, BorderLayout.EAST);

		updateCSI(csi);
	}

	/**
	 * Toggles the "clear" button's visibility
	 * 
	 * @param b boolean flag, true mean visible, false not visible
	 */
	public void setClearButtonVisible(boolean b) {
		clearButton.setVisible(b);
	}

	/**
	 * Sets the current charset for this component, and updates any listeners with that change.
	 * 
	 * @param newCS a {@link Charset}, or null to deselect
	 */
	public void setCharset(Charset newCS) {
		updateCSI(newCS != null ? CharsetInfoManager.getInstance().get(newCS) : null);

		ItemEvent e = newCS != null
				? new ItemEvent(this, ItemEvent.ITEM_FIRST, newCS, ItemEvent.SELECTED)
				: new ItemEvent(this, ItemEvent.ITEM_FIRST, null, ItemEvent.DESELECTED);
		listeners.invoke().itemStateChanged(e);
	}

	/**
	 * Sets the current charset for this component, and updates any listeners with that change.
	 * 
	 * @param name string name of a {@link Charset}, or null to deselect
	 */
	public void setCharsetName(String name) {
		CharsetInfo newCSI = name != null && !name.isBlank()
				? CharsetInfoManager.getInstance().get(name, StandardCharsets.US_ASCII)
				: null;

		updateCSI(newCSI);

		ItemEvent e = newCSI != null
				? new ItemEvent(this, ItemEvent.ITEM_FIRST, newCSI.getCharset(), ItemEvent.SELECTED)
				: new ItemEvent(this, ItemEvent.ITEM_FIRST, null, ItemEvent.DESELECTED);
		listeners.invoke().itemStateChanged(e);
	}

	/**
	 * {@return the name of the current charset, or null if no charset is selected}
	 */
	public String getCharsetName() {
		return csi != null ? csi.getName() : null;
	}

	/**
	 * {@return the current charset, or null if none selected}
	 */
	public Charset getCharset() {
		return csi != null ? csi.getCharset() : null;
	}

	/**
	 * {@return the current charset's CharsetInfo}
	 */
	public CharsetInfo getCharsetInfo() {
		return csi;
	}

	@Override
	public void setToolTipText(String text) {
		super.setToolTipText(text);
		updateCSI(csi);
	}

	private void clearCharset() {
		updateCSI(null);

		ItemEvent e = new ItemEvent(this, ItemEvent.ITEM_FIRST, null, ItemEvent.SELECTED);
		listeners.invoke().itemStateChanged(e);
	}

	private void chooseCharset() {
		CharsetInfo newCSI = CharsetPickerDialog.pickCharset(csi);
		if (newCSI != null) {
			updateCSI(newCSI);

			ItemEvent e =
				new ItemEvent(this, ItemEvent.ITEM_FIRST, newCSI.getCharset(), ItemEvent.SELECTED);

			listeners.invoke().itemStateChanged(e);
		}
	}

	private void updateCSI(CharsetInfo newCSI) {
		this.csi = newCSI;

		String baseTT = Objects.requireNonNullElse(getToolTipText(), "");
		if (csi != null) {
			if (!baseTT.isEmpty()) {
				baseTT += "<br><br>";
			}
			String desc = Objects.requireNonNullElse(newCSI.getComment(), "N/A");

			boolean needsHTML = !HTMLUtilities.isHTML(baseTT);

			charsetTF.setText(newCSI.getName());
			charsetTF.setToolTipText("""
					%s%s
					Charset: <b>%s</b><br>
					<br>
					Description: <b>%s</b>""".formatted(
					needsHTML ? "<html>" : "", 
					baseTT, 
					newCSI.getName(),
					HTMLUtilities.lineWrapWithHTMLLineBreaks(desc, 50)));
		}
		else {
			charsetTF.setText("");
			charsetTF.setToolTipText(baseTT);
		}
	}

	@Override
	public Object[] getSelectedObjects() {
		return csi != null ? new Object[] { csi.getCharset() } : new Object[0];
	}

	@Override
	public void addItemListener(ItemListener l) {
		listeners.add(l);
	}

	@Override
	public void removeItemListener(ItemListener l) {
		listeners.remove(l);
	}

}
