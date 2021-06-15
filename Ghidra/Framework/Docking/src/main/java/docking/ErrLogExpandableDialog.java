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
package docking;

import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.dnd.DnDConstants;
import java.awt.event.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.tree.TreePath;

import docking.widgets.label.GHtmlLabel;
import docking.widgets.tree.*;
import docking.widgets.tree.support.GTreeDragNDropHandler;
import ghidra.util.*;
import ghidra.util.exception.MultipleCauses;
import ghidra.util.html.HTMLElement;
import resources.ResourceManager;
import util.CollectionUtils;

public class ErrLogExpandableDialog extends AbstractErrDialog {
	public static ImageIcon IMG_REPORT = ResourceManager.loadImage("images/report.png");
	public static ImageIcon IMG_EXCEPTION = ResourceManager.loadImage("images/exception.png");
	public static ImageIcon IMG_FRAME_ELEMENT =
		ResourceManager.loadImage("images/StackFrameElement.png");
	public static ImageIcon IMG_STACK = ResourceManager.loadImage("images/StackFrame_Red.png");
	public static ImageIcon IMG_CAUSE = ResourceManager.loadImage("images/cause.png");

	private static final String SEND = "Send Report...";
	private static final String DETAIL = "Details >>>";
	private static final String CLOSE = "<<< Details";

	/** tracks 'details panel' open state across invocations */
	private static boolean showingDetails = false;

	protected ReportRootNode root;
	protected GTree tree;
	private List<Throwable> errors = new ArrayList<>();
	private String baseTitle;

	/** This spacer addresses the optical impression that the message panel changes size when showing details */
	protected Component horizontalSpacer;
	protected JButton detailButton;
	protected JButton sendButton;

	protected JPopupMenu popup;

	protected ErrLogExpandableDialog(String title, String msg, Throwable throwable) {
		super(title);

		baseTitle = title;
		errors.add(throwable);

		popup = new JPopupMenu();
		JMenuItem menuCopy = new JMenuItem("Copy");
		menuCopy.setActionCommand((String) TransferHandler.getCopyAction().getValue(Action.NAME));
		menuCopy.addActionListener(new TransferActionListener());
		menuCopy.setAccelerator(
			KeyStroke.getKeyStroke(KeyEvent.VK_C, DockingUtils.CONTROL_KEY_MODIFIER_MASK));
		popup.add(menuCopy);

		JPanel workPanel = new JPanel(new BorderLayout());
		JPanel msgPanel = new JPanel();
		msgPanel.setLayout(new BorderLayout(16, 16));
		msgPanel.setBorder(new EmptyBorder(16, 16, 16, 16));
		{
			JLabel msgText = new GHtmlLabel(getHTML(msg, CollectionUtils.asSet(throwable))) {
				@Override
				public Dimension getPreferredSize() {
					// rendering HTML the label can expand larger than the screen; keep it reasonable
					Dimension size = super.getPreferredSize();
					size.width = 300;
					return size;
				}
			};
			msgText.setIcon(UIManager.getIcon("OptionPane.errorIcon"));
			msgPanel.add(msgText, BorderLayout.CENTER);

			Box buttonBox = Box.createVerticalBox();
			{
				sendButton = new JButton(SEND);
				sendButton.addActionListener(e -> sendCallback());
				sendButton.setMaximumSize(
					new Dimension(Short.MAX_VALUE, sendButton.getPreferredSize().height));
				if (ErrLogDialog.getErrorReporter() != null) {
					buttonBox.add(sendButton);
					buttonBox.add(Box.createVerticalStrut(16));
				}

				detailButton = new JButton(showingDetails ? CLOSE : DETAIL);
				detailButton.addActionListener(e -> detailCallback());
				detailButton.setMaximumSize(
					new Dimension(Short.MAX_VALUE, detailButton.getPreferredSize().height));
				buttonBox.add(detailButton);
			}
			msgPanel.add(buttonBox, BorderLayout.EAST);

			horizontalSpacer = Box.createVerticalStrut(10);
			horizontalSpacer.setVisible(showingDetails);
			msgPanel.add(horizontalSpacer, BorderLayout.SOUTH);
		}
		workPanel.add(msgPanel, BorderLayout.NORTH);

		Box workBox = Box.createVerticalBox();
		{

			root = new ReportRootNode(getTitle(), CollectionUtils.asSet(throwable));
			tree = new GTree(root) {

				@Override
				public Dimension getPreferredSize() {
					Dimension dim = super.getPreferredSize();
					dim.height = 400;
					dim.width = 800; // trial and error?
					return dim;
				}
			};

			for (GTreeNode node : CollectionUtils.asIterable(root.iterator(true))) {
				if (node instanceof ReportExceptionNode) {
					tree.expandTree(node);
				}
			}

			tree.setSelectedNode(root.getChild(0));
			tree.setVisible(showingDetails);
			ExcTreeTransferHandler handler = new ExcTreeTransferHandler(root);
			tree.setDragNDropHandler(handler);
			tree.setTransferHandler(handler);
			ActionMap map = tree.getActionMap();
			map.put(TransferHandler.getCopyAction().getValue(Action.NAME),
				TransferHandler.getCopyAction());
			tree.addMouseListener(new MouseAdapter() {
				@Override
				public void mousePressed(MouseEvent e) {
					maybeShowPopup(e);
				}

				@Override
				public void mouseReleased(MouseEvent e) {
					maybeShowPopup(e);
				}

				private void maybeShowPopup(MouseEvent e) {
					if (e.isPopupTrigger()) {
						popup.show(e.getComponent(), e.getX(), e.getY());
					}
				}
			});

			workBox.add(tree);
		}
		workPanel.add(workBox, BorderLayout.CENTER);
		repack();

		addWorkPanel(workPanel);

		addDismissButton();
	}

	private String getHTML(String msg, Collection<Throwable> report) {

		// 
		// Usage question: The content herein will be escaped unless you call addHTMLContenet().
		//                 Further, clients can provide messages that contain HTML.  Is there a
		//                 use case where we want to show escaped HTML content?
		//
		//                 For now, I will assume no such use case exists, and allow HTML to go 
		//                 through.
		//
		//                 If no such use case exists, then we should update HTMLElement to 
		//                 not escape HTML.  If it does exist, then we should put the onus on
		//                 the client.
		//

		HTMLElement html = new HTMLElement("html");
		HTMLElement body = html.addElement("body");

		if (msg != null) {
			if (msg.startsWith(HTMLUtilities.HTML)) {
				// already HTML from the user
				body.addHTMLContent(msg);
			}
			else {
				String withBRs = addBR(msg);
				body./*addElement("h3").*/addHTMLContent(withBRs);
			}
		}

		for (Throwable t : report) {
			String tMsg = getMessage(t);

			if (SystemUtilities.isEqual(msg, tMsg)) {
				// Don't put the same message on twice.  Some clients call this dialog with
				// the message as simply Throwable.getMessage().
				continue;
			}

			String htmlTMsg = addBR(tMsg);
			body.addElement("p").addHTMLContent(htmlTMsg);
		}
		return html.toString();
	}

	private String addBR(String text) {
		String withBRs = HTMLUtilities.lineWrapWithHTMLLineBreaks(text, 0);
		return withBRs;
	}

	private String getMessage(Throwable t) {
		String message = t.getMessage();
		if (message != null) {
			return message;
		}
		return t.getClass().getSimpleName();
	}

	private void detailCallback() {
		showingDetails = !showingDetails;
		tree.setVisible(showingDetails);
		horizontalSpacer.setVisible(showingDetails);
		detailButton.setText(showingDetails ? CLOSE : DETAIL);
		repack();
	}

	private void sendCallback() {
		String details = root.collectReportText(null, 0).trim();
		String title = getTitle();
		close();
		ErrLogDialog.getErrorReporter().report(rootPanel, title, details);
	}

	@Override
	public Dimension getPreferredSize() {
		Dimension dim = super.getPreferredSize();
		dim.width = 600;
		return dim;
	}

	@Override
	public void addException(String message, Throwable t) {

		int n = errors.size();
		if (n > MAX_EXCEPTIONS) {
			return;
		}

		errors.add(t);
		root.addNode(new ReportExceptionNode(t));
		updateTitle(); // signal the new error
	}

	@Override
	int getExceptionCount() {
		return root.getChildCount();
	}

	@Override
	String getBaseTitle() {
		return baseTitle;
	}

	@Override
	public String getMessage() {
		return root.getReportText();
	}

	static interface NodeWithText {
		public String getReportText();

		public String collectReportText(Collection<? extends GTreeNode> included, int indent);

		public boolean doesIndent();

		public static class Util {
			public static final String INDENTATION = "    ";

			public static String collectReportText(GTreeNode cur,
					Collection<? extends GTreeNode> included, int indent) {
				StringBuilder b = new StringBuilder();
				if (cur instanceof NodeWithText) {
					NodeWithText nwt = (NodeWithText) cur;
					String text = nwt.getReportText();
					if (text != null) {
						b.append('\n');
						for (int i = 0; i < indent; i++) {
							b.append(INDENTATION);
						}
						b.append(nwt.getReportText());
					}
					if (nwt.doesIndent()) {
						indent += 1;
					}
				}
				boolean doAll = (included == null || !containsAny(included, cur.getChildren()));
				for (GTreeNode node : cur.getChildren()) {
					if (node instanceof NodeWithText && (doAll || included.contains(node))) {
						NodeWithText nwt = (NodeWithText) node;

						b.append(nwt.collectReportText(included, indent));
					}
				}
				return b.toString();
			}

			public static boolean containsAny(Collection<? extends GTreeNode> included,
					Collection<GTreeNode> allChildren) {
				Set<GTreeNode> res = new HashSet<>();
				res.addAll(included);
				res.retainAll(allChildren);
				return !res.isEmpty();
			}
		}
	}

	static class ReportRootNode extends GTreeNode implements NodeWithText {
		protected Collection<? extends Throwable> report;
		protected String title;
		protected boolean loaded = false;

		public ReportRootNode(String title, Collection<? extends Throwable> report) {
			this.title = title;
			this.report = report;
			for (Throwable exc : report) {
				addNode(new ReportExceptionNode(exc));
			}
		}

		@Override
		public String getName() {
			return title;
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return IMG_REPORT;
		}

		@Override
		public String getToolTip() {
			return "List of exceptions that occurred during relocation";
		}

		@Override
		public boolean isLeaf() {
			return false;
		}

		@Override
		public String getReportText() {
			return "Error Report: " + title + "\n";
		}

		@Override
		public String collectReportText(Collection<? extends GTreeNode> included, int indent) {
			return Util.collectReportText(this, included, indent);
		}

		@Override
		public boolean doesIndent() {
			return false;
		}
	}

	static class ReportExceptionNode extends GTreeLazyNode implements NodeWithText {
		protected Throwable exc;
		protected boolean loaded = false;

		public ReportExceptionNode(Throwable cause) {
			this.exc = cause;
		}

		@Override
		public String getName() {
			return getPrefix() + ": " + exc.toString();
		}

		@Override
		protected List<GTreeNode> generateChildren() {
			List<GTreeNode> list = new ArrayList<>();
			list.add(new ReportStackTraceNode(exc));
			Throwable c = exc.getCause();
			if (c != null) {
				if (c instanceof MultipleCauses) {
					for (Throwable t : ((MultipleCauses) c).getCauses()) {
						list.add(new ReportExceptionNode(t));
					}
				}
				else {
					list.add(new ReportCauseNode(c));
				}
			}
			return list;
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return IMG_EXCEPTION;
		}

		@Override
		public String getToolTip() {
			return "An exception occurred";
		}

		@Override
		public boolean isLeaf() {
			return false;
		}

		protected String getPrefix() {
			return "Exception";
		}

		@Override
		public String getReportText() {
			return getName();
		}

		@Override
		public String collectReportText(Collection<? extends GTreeNode> included, int indent) {
			return Util.collectReportText(this, included, indent);
		}

		@Override
		public boolean doesIndent() {
			return true;
		}
	}

	static class ReportStackTraceNode extends GTreeLazyNode implements NodeWithText {
		protected Throwable exc;
		protected boolean loaded = false;

		public ReportStackTraceNode(Throwable cause) {
			this.exc = cause;
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return IMG_STACK;
		}

		@Override
		protected List<GTreeNode> generateChildren() {
			List<GTreeNode> list = new ArrayList<>();
			for (StackTraceElement te : exc.getStackTrace()) {
				list.add(new ReportStackFrameNode(te));
			}
			return list;
		}

		@Override
		public String getName() {
			return "Stack Trace";
		}

		@Override
		public String getToolTip() {
			return "Stack Trace for " + exc.toString();
		}

		@Override
		public boolean isLeaf() {
			return false;
		}

		@Override
		public String getReportText() {
			return null;
		}

		@Override
		public String collectReportText(Collection<? extends GTreeNode> included, int indent) {
			return Util.collectReportText(this, included, indent);
		}

		@Override
		public boolean doesIndent() {
			return false;
		}
	}

	static class ReportCauseNode extends ReportExceptionNode {
		public ReportCauseNode(Throwable cause) {
			super(cause);
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return IMG_CAUSE;
		}

		@Override
		public String getToolTip() {
			return "The cause of the above exception";
		}

		@Override
		public String getPrefix() {
			return "Caused by";
		}
	}

	static class ReportStackFrameNode extends GTreeNode implements NodeWithText {
		private StackTraceElement te;

		public ReportStackFrameNode(StackTraceElement te) {
			this.te = te;
		}

		@Override
		public String getName() {
			return "at " + te.toString();
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return IMG_FRAME_ELEMENT;
		}

		@Override
		public String getToolTip() {
			return "Stack trace element";
		}

		@Override
		public boolean isLeaf() {
			return true;
		}

		@Override
		public String getReportText() {
			return getName();
		}

		@Override
		public String collectReportText(Collection<? extends GTreeNode> included, int indent) {
			return Util.collectReportText(this, included, indent);
		}

		@Override
		public boolean doesIndent() {
			return false;
		}
	}

	private static class ExcTreeTransferHandler extends TransferHandler
			implements GTreeDragNDropHandler {

		protected ReportRootNode root;

		public ExcTreeTransferHandler(ReportRootNode root) {
			this.root = root;
		}

		@Override
		public DataFlavor[] getSupportedDataFlavors(List<GTreeNode> transferNodes) {
			return new DataFlavor[] { DataFlavor.stringFlavor };
		}

		@Override
		protected Transferable createTransferable(JComponent c) {
			ArrayList<GTreeNode> nodes = new ArrayList<>();
			for (TreePath path : ((JTree) c).getSelectionPaths()) {
				nodes.add((GTreeNode) path.getLastPathComponent());
			}
			try {
				return new StringSelection(
					(String) getTransferData(nodes, DataFlavor.stringFlavor));
			}
			catch (UnsupportedFlavorException e) {
				Msg.debug(this, e.getMessage(), e);
			}
			return null;
		}

		@Override
		public Object getTransferData(List<GTreeNode> transferNodes, DataFlavor flavor)
				throws UnsupportedFlavorException {
			if (flavor != DataFlavor.stringFlavor) {
				throw new UnsupportedFlavorException(flavor);
			}
			if (transferNodes.isEmpty()) {
				return null;
			}
			if (transferNodes.size() == 1) {
				GTreeNode node = transferNodes.get(0);
				if (node instanceof NodeWithText) {
					return ((NodeWithText) node).collectReportText(transferNodes, 0).trim();
				}
				return null;
			}
			return root.collectReportText(transferNodes, 0).trim();
		}

		@Override
		public boolean isStartDragOk(List<GTreeNode> dragUserData, int dragAction) {
			for (GTreeNode node : dragUserData) {
				if (node instanceof NodeWithText) {
					return true;
				}
			}
			return false;
		}

		@Override
		public int getSupportedDragActions() {
			return DnDConstants.ACTION_COPY;
		}

		@Override
		public int getSourceActions(JComponent c) {
			return COPY;
		}

		@Override
		public boolean isDropSiteOk(GTreeNode destUserData, DataFlavor[] flavors, int dropAction) {
			return false;
		}

		@Override
		public void drop(GTreeNode destUserData, Transferable transferable, int dropAction) {
			throw new UnsupportedOperationException();
		}
	}

}

class TransferActionListener implements ActionListener, PropertyChangeListener {
	private JComponent focusOwner = null;

	public TransferActionListener() {
		KeyboardFocusManager manager = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		manager.addPropertyChangeListener("permanentFocusOwner", this);
	}

	@Override
	public void propertyChange(PropertyChangeEvent e) {
		Object o = e.getNewValue();
		if (o instanceof JComponent) {
			focusOwner = (JComponent) o;
		}
		else {
			focusOwner = null;
		}
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		if (focusOwner == null) {
			return;
		}
		String action = e.getActionCommand();
		Action a = focusOwner.getActionMap().get(action);
		if (a != null) {
			a.actionPerformed(new ActionEvent(focusOwner, ActionEvent.ACTION_PERFORMED, null));
		}
	}
}
