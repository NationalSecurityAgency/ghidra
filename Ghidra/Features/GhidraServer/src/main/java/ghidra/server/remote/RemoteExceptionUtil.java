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

import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RemoteExceptionUtil {

	private static final Logger log = LogManager.getLogger(RemoteExceptionUtil.class);

	/**
	 * Allowed IOExceptions (without cause) that are also defined by 
	 * {@code ghidra/Ghidra/Framework/FileSystem/data/client.rmi.serial.filter}.
	 */
	private static final Set<Class<? extends IOException>> allowedIOExceptionClassSet = Set.of(
		java.io.IOException.class,
		java.io.FileNotFoundException.class,
		ghidra.framework.store.ExclusiveCheckoutException.class,
		ghidra.util.exception.UserAccessException.class,
		ghidra.util.exception.DuplicateFileException.class,
		ghidra.util.exception.FileInUseException.class,
		ghidra.util.ReadOnlyException.class);

	/**
	 * Sanitize, log and dispatch exceptions to client and comply with client serialization 
	 * requirements.  Any IOException with a cause will be simplified to an IOException without
	 * a cause.  Any other checked exception, {@link RuntimeException}, {@link Throwable} or 
	 * {@link Error} will be logged and produce a simplified {@link  RemoteException} without cause.
	 * 
	 * @param t original exception/error (expected non-IOExceptions which are explicitly thrown should
	 * be caught and conveyed by called instead of passing to this method).
	 * @param logDetail operation descipription (required)
	 * @param user user if known else null
	 * @return IOException to be thrown
	 */
	static IOException dispatchIOException(Throwable t, String logDetail, String user) {
		return dispatchIOException(t, null, null, logDetail, user);
	}

	/**
	 * Sanitize, log and dispatch exceptions to client and comply with client serialization 
	 * requirements.  Any IOException with a cause will be simplified to an IOException without
	 * a cause.  Any other checked exception, {@link RuntimeException}, {@link Throwable} or 
	 * {@link Error} will be logged and produce a simplified {@link  RemoteException} without cause.
	 * 
	 * @param t original exception/error (expected non-IOExceptions which are explicitly thrown should
	 * be caught and conveyed by called instead of passing to this method).
	 * @param repositoryName repository name or null
	 * @param path repository folder/item path or null
	 * @param logDetail operation descipription (required)
	 * @param user user if known else null
	 * @return IOException to be thrown
	 */
	static IOException dispatchIOException(Throwable t, String repositoryName, String path,
			String logDetail, String user) {

		if (t instanceof RemoteException re) {
			// Assume this was triggered by a failed remote object instantiation
			return re;
		}

		Class<?> excClass = t.getClass();
		Throwable cause = t.getCause();
		String excKind;

		if (t instanceof IOException ioe) {

			// Only return allowed IOException class which has no cause
			if (cause == null && allowedIOExceptionClassSet.contains(excClass)) {
				return ioe;
			}

			// Log any IOException which has a cause or is not in the allowed set.  
			// Return as simple IOException without a cause.
			log.error(excClass.getName() + ": " + t.getMessage(), t);
			return new IOException(ioe.getMessage());
		}

		if (t instanceof RuntimeException rte) {
			excKind = "Runtime Exception";
		}
		else if (t instanceof Exception) {
			// Unexpected condition: exception should have been caught and handled by caller
			excKind = "Checked Exception";
		}
		else {
			excKind = "Error";
		}

		// Log all non-IOExceptions and return as a RemoteException without cause.
		RemoteLoggingUtil.log(repositoryName, path, "ERROR: " + logDetail, user, true);
		log.error(excKind + ": " + t, t);
		return new RemoteException("Unexpected Server " + excKind);
	}

	private RemoteExceptionUtil() {
		// No instantiation
	}

}
