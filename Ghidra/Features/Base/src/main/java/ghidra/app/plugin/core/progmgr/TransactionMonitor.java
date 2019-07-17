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
package ghidra.app.plugin.core.progmgr;

import java.awt.Dimension;
import java.awt.Graphics;
import java.util.Iterator;
import java.util.List;

import javax.swing.*;

import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.Transaction;
import ghidra.framework.model.TransactionListener;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.util.HTMLUtilities;
import resources.ResourceManager;

class TransactionMonitor extends JComponent implements TransactionListener {

	private static ImageIcon busyIcon;
	private static Dimension prefSize;

	ProgramDB program;
	Transaction lastTx;

	TransactionMonitor() {
		super();
		busyIcon = ResourceManager.loadImage("images/editbytes.gif");
		prefSize = new Dimension(busyIcon.getIconWidth(), busyIcon.getIconHeight());
		ToolTipManager.sharedInstance().registerComponent(this);
	}

	void setProgram(Program p) {
		if (program != null) {
			program.removeTransactionListener(this);
		}
		if (p instanceof ProgramDB) {
			program = (ProgramDB) p;
			program.addTransactionListener(this);
		}
		else {
			program = null;
		}
		lastTx = null;
		repaint();
	}

	/**
	 * @see ghidra.framework.model.TransactionListener#transactionStarted(ghidra.framework.data.DomainObjectAdapterDB, ghidra.framework.model.Transaction)
	 */
	@Override
	public void transactionStarted(DomainObjectAdapterDB domainObj, Transaction tx) {
		lastTx = tx;
		repaint();
	}

	/**
	 * @see ghidra.framework.model.TransactionListener#transactionEnded(ghidra.framework.data.DomainObjectAdapterDB)
	 */
	@Override
	public void transactionEnded(DomainObjectAdapterDB domainObj) {
		lastTx = null;
		repaint();
	}

	/**
	 * @see ghidra.framework.model.TransactionListener#undoStackChanged(ghidra.framework.data.DomainObjectAdapterDB)
	 */
	@Override
	public void undoStackChanged(DomainObjectAdapterDB domainObj) {
		// don't care
	}

	@Override
	public void undoRedoOccurred(DomainObjectAdapterDB domainObj) {
		// don't care
	}

	/**
	 * @see java.awt.Component#getPreferredSize()
	 */
	@Override
	public Dimension getPreferredSize() {
		return new Dimension(prefSize);
	}

	/**
	 * @see javax.swing.JComponent#paintComponent(java.awt.Graphics)
	 */
	@Override
	protected void paintComponent(Graphics g) {
		g.setColor(getBackground());
		g.fillRect(0, 0, getWidth(), getHeight());
		if (lastTx != null) {
			busyIcon.paintIcon(this, g, 0, 0);
		}
	}

	/**
	 * @see javax.swing.JComponent#getToolTipText()
	 */
	@Override
	public String getToolTipText() {
		if (lastTx != null) {
			List<String> list = lastTx.getOpenSubTransactions();
			StringBuffer tip = new StringBuffer();
			Iterator<String> iter = list.iterator();
			while (iter.hasNext()) {
				if (tip.length() != 0) {
					tip.append('\n');
				}
				tip.append(iter.next());
			}
			return HTMLUtilities.toHTML(tip.toString());
		}
		return null;
	}

}
