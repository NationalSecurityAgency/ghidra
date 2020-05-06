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
package ghidra.app.plugin.core.osgi;

import java.util.stream.Collectors;

import org.osgi.framework.Bundle;
import org.osgi.framework.BundleException;

public class GhidraBundleException extends OSGiException {
	private Bundle bundle;
	private String bundle_loc;

	public GhidraBundleException(Bundle bundle, String msg, BundleException cause) {
		super(msg + ": " + parsedCause(cause), cause);
		this.bundle = bundle;
	}

	public GhidraBundleException(String bundle_loc, String msg, BundleException cause) {
		super(msg + ": " + parsedCause(cause), cause);
		this.bundle_loc = bundle_loc;
	}

	public Bundle getBundle() {
		return bundle;
	}

	public String getBundleLocation() {
		return bundle_loc != null ? bundle_loc : bundle.getLocation();
	}

	static private String parsedCause(Throwable e) {
		if (e == null) {
			return "";
		}
		if (e instanceof BundleException) {
			BundleException be = (BundleException) e;
			switch (be.getType()) {
				default:
					return "No exception type";
				case BundleException.UNSPECIFIED:
					return "UNSPECIFIED";
				/**
				 * The operation was unsupported. This type can be used anywhere a
				 * BundleException can be thrown.
				 */
				case BundleException.UNSUPPORTED_OPERATION:
					return "UNSUPPORTED_OPERATION";

				/**
				 * The operation was invalid.
				 */
				case BundleException.INVALID_OPERATION:
					return "INVALID_OPERATION";

				/**
				 * The bundle manifest was in error.
				 */
				case BundleException.MANIFEST_ERROR:
					return "MANIFEST_ERROR";

				/**
				 * The bundle was not resolved.
				 */
				case BundleException.RESOLVE_ERROR: {
					String message = be.getMessage();
					if (message.startsWith("Unable to acquire global lock")) {
						return message;
					}
					// parse the package constraints from filters in the BundleRequirement string
					String packages =
						OSGiUtils.extractPackages(be.getMessage()).stream().distinct().collect(
							Collectors.joining("\n"));
					return "RESOLVE_ERROR with reference to packages:\n" + packages;
				}

				/**
				 * The bundle activator was in error.
				 */
				case BundleException.ACTIVATOR_ERROR:
					return "ACTIVATOR_ERROR";

				/**
				 * The operation failed due to insufficient permissions.
				 */
				case BundleException.SECURITY_ERROR:
					return "SECURITY_ERROR";

				/**
				 * The operation failed to complete the requested lifecycle state change.
				 */
				case BundleException.STATECHANGE_ERROR:
					return "STATECHANGE_ERROR";

				/**
				 * The bundle could not be resolved due to an error with the
				 * Bundle-NativeCode header.
				 */
				case BundleException.NATIVECODE_ERROR:
					return "NATIVECODE_ERROR";

				/**
				 * The install or update operation failed because another already installed
				 * bundle has the same symbolic name and version. This exception type will
				 * only occur if the framework is configured to only allow a single bundle
				 * to be installed for a given symbolic name and version.
				 * 
				 * @see Constants#FRAMEWORK_BSNVERSION
				 */
				case BundleException.DUPLICATE_BUNDLE_ERROR:
					return "DUPLICATE_BUNDLE_ERROR";

				/**
				 * The start transient operation failed because the start level of the
				 * bundle is greater than the current framework start level
				 */
				case BundleException.START_TRANSIENT_ERROR:
					return "START_TRANSIENT_ERROR";

				/**
				 * The framework received an error while reading the input stream for a
				 * bundle.
				 */
				case BundleException.READ_ERROR:
					return "READ_ERROR";

				/**
				 * A framework hook rejected the operation.
				 * 
				 * @since 1.6
				 */
				case BundleException.REJECTED_BY_HOOK:
					return "REJECTED_BY_HOOK";
			}
		}
		return e.getCause().getMessage();
	}

}
