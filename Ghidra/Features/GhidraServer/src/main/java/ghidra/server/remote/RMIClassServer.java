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
package ghidra.server.remote;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;

import ghidra.util.Msg;

/**
 * <code>RMIClassServer</code> provides a server for serializing classes to an 
 * RMI client as needed.  This implementation starts a new listener thread each
 * time a connection is accepted.
 */
public class RMIClassServer implements Runnable {

	private static RMIClassServer classServer;
	
	private ServerSocket server;
	
	private ArrayList<Thread> threads = new ArrayList<Thread>();
	
	/**
	 * Construct a new server. 
	 * @param port
	 * @throws IOException if port is in use or not permitted.
	 */
	private RMIClassServer(int port) throws IOException {
		if (classServer != null) {
			throw new RuntimeException("Class server already running");
		}
		classServer = this;
		server = new ServerSocket(port);
		newListener();
	}

	private void dispose() {
		synchronized (RMIClassServer.class) {
			classServer = null;
			for (Thread t : threads) {
				t.interrupt();
			}
			if (server != null) {
				try {
					server.close();
				} catch (IOException e) {
				}
				server = null;
			}
		}
	}
	
	private void newListener() {
		synchronized (RMIClassServer.class) {
			if (classServer == this) { // make sure we have not been stopped
				Thread t = new Thread(this, "RMI Class Server");
				threads.add(t);
				t.start();
			}
		}
	}

	/*
	 * @see java.lang.Runnable#run()
	 */
	public void run() {

		// accept connection
		Socket socket = null;
		try {
			socket = server.accept();
		} catch (NullPointerException e) {
			// Just in case server is null after dispose
		} catch (InterruptedIOException e) {
		} catch (Throwable t) {
		    Msg.error(this, "Class server error: " + t.toString(), t);
		} 
			
		synchronized (RMIClassServer.class) {
			
			// create a new thread to accept the next connection
			newListener();
		
			if (socket == null) {
				threads.remove(Thread.currentThread());
				return;
			}
		}

		try {
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			try {
				// get path to class file
				DataInputStream in = new DataInputStream(socket.getInputStream());
				String path = getClassName(in);

				byte[] bytecodes = getBytes(path);

				// send bytecodes  in response (assumes HTTP/1.0 or later)
				try {
					out.writeBytes("HTTP/1.0 200 OK\r\n");
					out.writeBytes("Content-Length: " + bytecodes.length + "\r\n");
					out.writeBytes("Content-Type: application/java\r\n\r\n");
					out.write(bytecodes);
					out.flush();
				} catch (IOException ie) {
					return;
				}
			} catch (Exception e) {
				// write out error response
				out.writeBytes("HTTP/1.0 400 " + e.getMessage() + "\r\n");
				out.writeBytes("Content-Type: text/html\r\n\r\n");
				out.flush();
			}
		} catch (InterruptedIOException e) {
		} catch (Throwable t) {
			// eat exception
		    Msg.error(this, "error writing response: " + t.getMessage(), t);
		}

		try {
			socket.close();
		} catch (IOException e) {
		} finally {
			synchronized (RMIClassServer.class) {
				threads.remove(Thread.currentThread());
			}
		}
	}
	
	/**
	 * Get the full classname requested or null if not a valid class file request.
	 * Consumes all input from client.
	 * @param in HTTP input stream
	 * @return class name including package prefix
	 * @throws IOException if request was not for a class file
	 */
	private String getClassName(DataInputStream in) throws IOException {
		String line = in.readLine();
		String path = "";
		
		if (line.startsWith("GET /")) {
			line = line.substring(5, line.length()-1).trim();
			int index = line.indexOf(".class");
			if (index != -1) {
				path = line.substring(0, index+6);
			}
		}
		
		// eat the rest of header
		do {
            line = in.readLine();
        } while ((line.length() != 0));
        
        if (path.length() != 0) {
        	return path;
        }
        throw new IOException("Malformed Header");
	}
	
	/**
	 * Get byte code data for specified classname
	 * @param classname full class name including package
	 * @return byte-code data for class
	 */
	private byte[] getBytes(String classname) throws IOException {

		InputStream istream = ClassLoader.getSystemResourceAsStream(classname);
		if (istream == null) {
			throw new IOException("Class not found");	
		}

		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			DataInputStream in = new DataInputStream(istream);
			byte[] buf = new byte[4096];
			int readLen = 0;
			while ((readLen = in.read(buf)) >= 0) {
				out.write(buf, 0, readLen);
			}
			return out.toByteArray();
		}
		finally {
			istream.close();
		}
	}
	
	/**
	 * Start a class file server.
	 * @param port port to use
	 */
	static synchronized void startServer(int port) throws IOException {
		new RMIClassServer(port);
	}

	/**
	 * Stop the class server if running
	 */
	static synchronized void stopServer() {
		if (classServer != null) {
			Msg.info(RMIClassServer.class, "Stopping class server...");
			classServer.dispose();
		}
	}
}

