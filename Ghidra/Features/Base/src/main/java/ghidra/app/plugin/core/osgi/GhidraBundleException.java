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

/**
 * {@link GhidraBundleException}s store the context associated with exceptions thrown during bundle operations.
 */
public class GhidraBundleException extends OSGiException {
	private final Bundle bundle;
	private final String bundleLocation;

	/**
	 * Construct a new exception originating with {@code bundle}.
	 * 
	 * @param bundle the bundle (if available)
	 * @param msg a contextual message
	 * @param cause the original exception
	 */
	public GhidraBundleException(Bundle bundle, String msg, BundleException cause) {
		super(msg + ": " + parsedCause(cause), cause);
		this.bundle = bundle;
		this.bundleLocation = bundle.getLocation();
	}

	/**
	 * Construct a new exception originating with the bundle having location identifier {@code bundleLocation}.
	 * 
	 * @param bundleLocation the bundle location identifier (since no bundle is available)
	 * @param msg a contextual message
	 * @param cause the original exception
	 */
	public GhidraBundleException(String bundleLocation, String msg, BundleException cause) {
		super(msg + ": " + parsedCause(cause), cause);
		this.bundle = null;
		this.bundleLocation = bundleLocation;
	}

	/**
	 * Construct a new exception originating with the bundle having location identifier {@code bundleLocation}.
	 * 
	 * @param bundleLocation the bundle location identifier (since no bundle is available)
	 * @param msg a contextual message
	 */
	public GhidraBundleException(String bundleLocation, String msg) {
		super(msg);
		this.bundle = null;
		this.bundleLocation = bundleLocation;
	}

	/**
	 * @return the associated bundle, or null.  If null, the bundle location identifier will be non-null
	 */
	public Bundle getBundle() {
		return bundle;
	}

	/**
	 * When no {@link Bundle} is available, {@link #getBundle()} will return {@code null}. 
	 * 
	 * @return the bundle location identifier of the offending bundle.
	 */
	public String getBundleLocation() {
		return bundleLocation != null ? bundleLocation : bundle.getLocation();
	}

	private static String parsedCause(Throwable e) {
		if (e == null) {
			return "";
		}
		if (e instanceof BundleException) {
			BundleException bundleException = (BundleException) e;
			switch (bundleException.getType()) {
				default:
					return "No exception type";
				case BundleException.UNSPECIFIED:
					return e.getMessage();
				// The operation was unsupported. This type can be used anywhere a BundleException can be thrown.
				case BundleException.UNSUPPORTED_OPERATION:
					return "UNSUPPORTED_OPERATION";

				// The operation was invalid.
				case BundleException.INVALID_OPERATION:
					return "INVALID_OPERATION";

				// The bundle manifest was in error.
				case BundleException.MANIFEST_ERROR:
					return "MANIFEST_ERROR";

				// The bundle was not resolved.
				case BundleException.RESOLVE_ERROR: {
					String message = bundleException.getMessage();
					if (message.startsWith("Unable to acquire global lock")) {
						return message;
					}
					// parse the package constraints from filters in the BundleRequirement string
					String packages = OSGiUtils
							.extractPackageNamesFromFailedResolution(bundleException.getMessage())
							.stream()
							.distinct()
							.collect(Collectors.joining("\n"));
					return "RESOLVE_ERROR - \n" + packages;
				}

				// The bundle activator was in error.
				case BundleException.ACTIVATOR_ERROR:
					return "ACTIVATOR_ERROR";

				// The operation failed due to insufficient permissions.
				case BundleException.SECURITY_ERROR:
					return "SECURITY_ERROR";

				// The operation failed to complete the requested lifecycle state change.
				case BundleException.STATECHANGE_ERROR:
					return "STATECHANGE_ERROR";

				// The bundle could not be resolved due to an error with the Bundle-NativeCode header.
				case BundleException.NATIVECODE_ERROR:
					return "NATIVECODE_ERROR";

				/*
				 * The install or update operation failed because another already installed
				 * bundle has the same symbolic name and version. This exception type will
				 * only occur if the framework is configured to only allow a single bundle
				 * to be installed for a given symbolic name and version.
				 * 
				 * @see Constants#FRAMEWORK_BSNVERSION
				 */
				case BundleException.DUPLICATE_BUNDLE_ERROR:
					return "DUPLICATE_BUNDLE_ERROR";

				// The start transient operation failed because the start level of the bundle 
				// is greater than the current framework start level
				case BundleException.START_TRANSIENT_ERROR:
					return "START_TRANSIENT_ERROR";

				// The framework received an error while reading the input stream for a bundle.
				case BundleException.READ_ERROR:
					return "READ_ERROR";

				// A framework hook rejected the operation.
				case BundleException.REJECTED_BY_HOOK:
					return "REJECTED_BY_HOOK";
			}
		}
		return e.getCause().getMessage();
	}

}
