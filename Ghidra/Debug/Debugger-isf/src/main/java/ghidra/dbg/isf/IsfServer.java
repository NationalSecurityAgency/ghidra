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
package ghidra.dbg.isf;

import java.io.*;
import java.net.*;
import java.util.HashMap;
import java.util.Map;

import db.DBHandle;
import generic.test.AbstractGTest;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraTestApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectData;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class IsfServer extends Thread {
	private ServerSocket server;

	private boolean running = false;
	private GhidraProject project;
	private int port = 54321;
	private IsfClientHandler handler;

	private Map<String, DataTypeManager> managers = new HashMap<>();

	public IsfServer(GhidraProject project, int port) {
		this.project = project;
		this.port = port;
		handler = new IsfClientHandler(this);
	}

	public void startServer() {
		try {
			server = new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
			this.start();
		}
		catch (IOException e) {
			throw new RuntimeException("Could not start server");
		}
	}

	public void stopServer() {
		running = false;
		this.interrupt();
		for (DataTypeManager m : managers.values()) {
			m.close();
		}
	}

	@Override
	public void run() {
		running = true;
		while (running) {
			try {
				Msg.info(this, "Listening for a connection...");

				Socket socket = server.accept();
				socket.setTcpNoDelay(true);

				Msg.info(this, "Connected - starting handler...");
				IsfConnectionHandler connectionHandler = new IsfConnectionHandler(socket, handler);
				connectionHandler.start();
			}
			catch (IOException e) {
				Msg.error(this, e);
			}
		}
	}

	public DataTypeManager getDataTypeManager(String ns) {
		synchronized (managers) {
			if (managers.containsKey(ns)) {
				return managers.get(ns);
			}
			try {
				DataTypeManager dtm;
				if (ns.endsWith(".gdt")) {
					dtm = openAsDataTypeArchive(ns);
				}
				else if (ns.endsWith(".gzf")) {
					dtm = openAsProgramDatabase(ns);
				}
				else {
					dtm = openAsProgramFile(ns);
				}
				managers.put(ns, dtm);
				return dtm;
			}
			catch (Exception e) {
				Msg.error(this, ns + " undefined namespace (should be .gdt, .gzf, or domain file)");
				return null;
			}
		}
	}

	private DataTypeManager openAsProgramFile(String ns) throws Exception {
		ProjectData projectData = project.getProjectData();
		DomainFile df = projectData.getFile(ns);
		if (!Program.class.isAssignableFrom(df.getDomainObjectClass())) {
			throw new IOException("File does not correspond to Program content: " + ns);
		}

		// FIXME: Need to track and release Program instance after DTM use is complete (GP-6895)
		Program program = (Program) df.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		return program.getDataTypeManager();
	}

	private DataTypeManager openAsDataTypeArchive(String ns) throws Exception {
		File gdt = new File(ns);
		return FileDataTypeManager.openFileArchive(gdt, false);
	}

	private DataTypeManager openAsProgramDatabase(String ns) throws Exception {
		File gzf = new File(ns);
		TaskMonitor dummy = TaskMonitor.DUMMY;
		PackedDatabase db = PackedDatabase.getPackedDatabase(gzf, dummy);

		DBHandle dbh = db.openForUpdate(dummy);

		Program p;
		boolean success = false;
		try {
			p = new ProgramDB(dbh, OpenMode.UPGRADE, dummy, this);
			success = true;
		}
		finally {
			if (!success) {
				dbh.close();
			}
		}

		// FIXME: Need to track and release Program instance after DTM use is complete (GP-6895)
		return p.getListing().getDataTypeManager();
	}

	public static void main(String[] args) throws FileNotFoundException, IOException {
		GhidraApplicationLayout layout =
			new GhidraTestApplicationLayout(new File(AbstractGTest.getTestDirectoryPath()));
		HeadlessGhidraApplicationConfiguration config =
			new HeadlessGhidraApplicationConfiguration();
		Application.initializeApplication(layout, config);

		IsfServer server = new IsfServer(null, 54321);
		server.startServer();
	}

}
