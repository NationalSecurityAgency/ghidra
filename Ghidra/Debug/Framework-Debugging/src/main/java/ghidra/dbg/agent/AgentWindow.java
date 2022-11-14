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
package ghidra.dbg.agent;

import java.awt.*;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.net.SocketAddress;

import javax.swing.*;
import javax.swing.text.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;

import ghidra.framework.LoggingInitialization;
import ghidra.util.Msg;
import ghidra.util.Swing;
import log.LogListener;
import log.LogPanelAppender;

public class AgentWindow extends JFrame implements WindowListener, LogListener {
	public static final int MAX_LOG_CHARS = 100000;

	protected final JTextPane logPane = new JTextPane();
	protected final JScrollPane logScroll = new JScrollPane(logPane);

	public AgentWindow(String title, SocketAddress localAddress) {
		super(title);
		setLayout(new BorderLayout());
		addWindowListener(this);
		add(new JLabel("<html>This agent is listening at <b>" + localAddress +
			"</b>. Close this window to terminate it.</html>"), BorderLayout.NORTH);
		logPane.setEditable(false);
		logPane.setFont(Font.decode(Font.MONOSPACED));
		logPane.setAutoscrolls(true);
		logScroll.setAutoscrolls(true);
		DefaultCaret caret = (DefaultCaret) logPane.getCaret();
		caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
		add(logScroll);
		setMinimumSize(new Dimension(400, 300));
		setVisible(true);

		System.setProperty("log4j.configurationFile", "agent.log4j.xml");
		LoggingInitialization.initializeLoggingSystem();
		LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
		Configuration config = ctx.getConfiguration();
		Appender appender = config.getAppender("logPanel");
		if (!(appender instanceof LogPanelAppender)) {
			Msg.error(this, "Couldn't find LogPanelAppender instance in the Log4j context. " +
				"Nothing will be logged to the agent's window.");
		}
		else {
			LogPanelAppender logPanelAppender = (LogPanelAppender) appender;
			logPanelAppender.setLogListener(this);
		}
	}

	@Override
	public void messageLogged(String message, boolean isError) {

		Swing.runIfSwingOrRunLater(() -> {
			MutableAttributeSet attributes = new SimpleAttributeSet();
			if (isError) {
				StyleConstants.setForeground(attributes, Color.RED);
			}
			Document document = logPane.getStyledDocument();
			try {
				document.insertString(document.getLength(), message + "\n", attributes);
				if (document.getLength() > MAX_LOG_CHARS) {
					document.remove(0, document.getLength() - MAX_LOG_CHARS);
				}
			}
			catch (BadLocationException e) {
				throw new AssertionError(e);
			}
		});
	}

	@Override
	public void windowOpened(WindowEvent e) {
		// Dont' care
	}

	@Override
	public void windowClosing(WindowEvent e) {
		System.out.println("User closed agent window. Exiting");
		System.exit(0);
	}

	@Override
	public void windowClosed(WindowEvent e) {
		// Dont' care
	}

	@Override
	public void windowIconified(WindowEvent e) {
		// Dont' care
	}

	@Override
	public void windowDeiconified(WindowEvent e) {
		// Dont' care
	}

	@Override
	public void windowActivated(WindowEvent e) {
		// Dont' care
	}

	@Override
	public void windowDeactivated(WindowEvent e) {
		// Dont' care
	}
}
