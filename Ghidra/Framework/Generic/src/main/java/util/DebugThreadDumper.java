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
package util;

import java.io.IOException;
import java.lang.Thread.State;
import java.lang.management.*;

import javax.management.MBeanServerConnection;
import javax.management.remote.*;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;

public class DebugThreadDumper implements GhidraLaunchable {

	// target must include the following VM argument on Sun JVM's
	//    -Dcom.sun.management.jmxremote.port=18002
	//    -Dcom.sun.management.jmxremote.authenticate=false
	//    -Dcom.sun.management.jmxremote.ssl=false

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) {

		if (args.length != 1) {
			System.err.println("Invalid usage, expected debug port number");
			System.exit(1);
		}

		int port = -1;
		try {
			port = Integer.parseInt(args[0]);
		}
		catch (NumberFormatException e) {
			// ignore
		}

		if (port <= 0 || port >= (64 * 1024 - 1)) {
			System.err.println("Invalid debug port number");
			System.exit(1);
		}

		int jmxPort = port + 1;
		System.out.println("Thread Dump (debug-port=" + port + ", jmx-port=" + jmxPort + ")");

		try {
			System.out.println("Connecting to VM...");
			String url = "service:jmx:rmi:///jndi/rmi://localhost:" + jmxPort + "/jmxrmi";
			JMXConnector connector = JMXConnectorFactory.connect(new JMXServiceURL(url));
			MBeanServerConnection connection = connector.getMBeanServerConnection();

			ThreadMXBean threadBean = ManagementFactory.newPlatformMXBeanProxy(connection,
				ManagementFactory.THREAD_MXBEAN_NAME, ThreadMXBean.class);

			// potential options
			// Dump Trace
			System.out.println("Dumping threads...");
			dumpThreads(threadBean);
		}
		catch (IOException e) {
			System.err.println("Error while dumping VM threads: " + e.getMessage());
		}
	}

	private void dumpThreads(ThreadMXBean threadBean) {

		//TODO: virtualMachine.suspend();  // suspend to get a snapshot of the threads

		for (ThreadInfo threadInfo : threadBean.dumpAllThreads(true, true)) {
			dumpThreadStack(threadInfo);
		}

		// TODO: virtualMachine.resume();   // resume for future use
	}

	private void dumpThreadStack(ThreadInfo threadInfo) {

		dumpThreadInfo(threadInfo);

		for (StackTraceElement stackElement : threadInfo.getStackTrace()) {
			System.out.println("\t" + buildLocationString(stackElement));
		}
	}

	private String buildLocationString(StackTraceElement stackElement) {
		StringBuffer buffer = new StringBuffer();

		String methodName = stackElement.getClassName() + "." + stackElement.getMethodName();
		buffer.append(methodName);

		String sourceName = stackElement.getFileName();
		buffer.append(" (").append(sourceName).append(":");

		int lineNumber = stackElement.getLineNumber();
		buffer.append(lineNumber < 0 ? "<unknown source>" : Integer.toString(lineNumber)).append(
			")");

		return buffer.toString();
	}

	private void dumpThreadInfo(ThreadInfo threadInfo) {

		State threadState = threadInfo.getThreadState();

		System.out.println("\n\"" + threadInfo.getThreadName() + "\"" + " id=" +
			threadInfo.getThreadId() + " state=" + threadState);
		String lockOwner = threadInfo.getLockOwnerName();
		long lockOwnerId = threadInfo.getLockOwnerId();
		String lockName = threadInfo.getLockName();
		if (lockOwner != null) {
			System.out.println("\tWaiting on Monitor:");
			System.out.println(
				"\t\t-" + lockName + ", owner: " + lockOwner + "(" + lockOwnerId + ")");
		}

		MonitorInfo[] monitorInfo = threadInfo.getLockedMonitors();
		if (monitorInfo != null && monitorInfo.length != 0) {
			System.out.println("\tOwned Monitors:");
			for (MonitorInfo monitor : monitorInfo) {
				System.out.println("\t\t-" + monitor);
			}
		}

		LockInfo[] lockedSynchronizers = threadInfo.getLockedSynchronizers();
		if (lockedSynchronizers != null && lockedSynchronizers.length != 0) {
			System.out.println("\tOwned Sychronizers:");
			for (LockInfo lock : lockedSynchronizers) {
				System.out.println("\t\t-" + lock);
			}
		}
	}

//    private void dumpThreadInfo( ThreadReference threadReference ) {
//        ReferenceType referenceType = threadReference.referenceType();
//        Field priorityField = referenceType.fieldByName( "priority" );
//        
//        System.out.println( "\n\"" + threadReference.name() + "\" " +
//                "priority=" + threadReference.getValue( priorityField ) +
//                " status=" + getThreadStatus( threadReference.status() ) +
//                " ");
//    }
//    
//    private String getThreadStatus( int statusCode ) {        
//        switch( statusCode ) {
//            case ThreadReference.THREAD_STATUS_NOT_STARTED:
//                return "not started";
//            case ThreadReference.THREAD_STATUS_RUNNING:
//                return "running";
//            case ThreadReference.THREAD_STATUS_SLEEPING:
//                return "sleeping";
//            case ThreadReference.THREAD_STATUS_UNKNOWN:
//                return "unknown";
//            case ThreadReference.THREAD_STATUS_WAIT:
//                return "waiting";
//            case ThreadReference.THREAD_STATUS_ZOMBIE:
//                return "zombie";
//            case ThreadReference.THREAD_STATUS_MONITOR:
//                return "waiting for monitor";
//            default: 
//                return "<unknown>";   
//        }
//    }

//    private AttachingConnector findLaunchingConnector() {
//        List<?> connectors = Bootstrap.virtualMachineManager().allConnectors();
//        Iterator<?> iter = connectors.iterator();
//        while (iter.hasNext()) {
//            Connector connector = (Connector)iter.next();
//            if (connector.name().equals("com.sun.jdi.SocketAttach")) {
//                return (AttachingConnector)connector;
//            }
//        }
//        throw new Error("No launching connector");
//    }
//
//    private Map<String, Argument> getConnectorArguments( AttachingConnector connector, String[] mainArguments ) {
//        Map<String, Argument> arguments = connector.defaultArguments();
//
//        // TODO: parse user arguments
//        // List<StringArgumentPair> argList = parseArguments( mainArguments );
//        
//        Argument argument = arguments.get( "port" );
//        if ( argument == null ) {
//            // no SocketConnector
//            throw new RuntimeException( "Unable to locate \"port\" argument" );
//        }
//        
//        setPortArgumentValue( argument, mainArguments );
//        
//        return arguments;
//    }
//
//    private static void setPortArgumentValue( Argument argument, String[] mainArguments ) {
//        StringBuffer buffer = new StringBuffer();
//        for ( int i = 0; i < mainArguments.length; i++ ) {
//            buffer.append( mainArguments[i] );
//        }
//        
//        StringTokenizer tokenizer = new StringTokenizer( buffer.toString(), " ,=" );
//        List<String> tokenList = new ArrayList<String>();
//        while ( tokenizer.hasMoreTokens() ) {
//            tokenList.add( tokenizer.nextToken() );
//        }            
//        
//        int portIndex = tokenList.indexOf( "port" );
//        if ( portIndex < 0 ) {
//            portIndex = tokenList.indexOf( "-port" );
//        }
//        
//        if ( portIndex < 0 ) {
//            return;
//        }
//        
//        String portValue = tokenList.get( portIndex + 1 );
//        String portStringValue = DEFAULT_PORT;
//        try {
//            // test to see if the value is a valid int
//            Integer.parseInt( portValue );
//            portStringValue = portValue;
//        }
//        catch ( NumberFormatException nfe ) {
//            System.out.println( "Unexpected port value: " + portValue );
//        }
//        
//        System.out.println("Using port: " + portStringValue );
//        argument.setValue( portStringValue );
//    }

}
