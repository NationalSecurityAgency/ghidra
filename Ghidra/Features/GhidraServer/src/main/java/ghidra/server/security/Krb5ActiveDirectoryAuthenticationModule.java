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
package ghidra.server.security;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import javax.security.auth.spi.LoginModule;

import com.sun.security.auth.module.Krb5LoginModule;

import ghidra.framework.remote.GhidraPrincipal;
import ghidra.server.UserManager;

/**
 * A Ghidra {@link AuthenticationModule} that authenticates against an Active Directory Kerberos system
 * using JAAS's {@link Krb5LoginModule}.
 * <p>
 * This auth module needs to know the Active Directory domain name, and then from there it can bootstrap
 * itself using DNS lookups to find the Kerberos server.
 * <p>
 * As this class sets some global Kerberos system properties, only one copy of this class should
 * be active in a JVM at a time.
 *
 */
public class Krb5ActiveDirectoryAuthenticationModule implements AuthenticationModule {

	private boolean allowUserToSpecifyName;
	private String domainName;
	private boolean stripDomainFromUsername = true;

	/**
	 * Creates a new {@link Krb5ActiveDirectoryAuthenticationModule} instance.
	 * <p>
	 *
	 * @param domainName the Active Directory domain name (ie. "yourdomain.tld")
	 * @param allowUserToSpecifyName flag, if true will include a {@link NameCallback} in the
	 * {@link #getAuthenticationCallbacks()} list, which allows the user to specify a different
	 * name than their {@link GhidraPrincipal}.
	 * @throws IllegalArgumentException if domainName is null or blank, or if the Microsoft
	 * Active Directory domain controller can not be looked-up in DNS.
	 */
	public Krb5ActiveDirectoryAuthenticationModule(String domainName,
			boolean allowUserToSpecifyName) throws IllegalArgumentException {
		this.domainName = domainName;
		this.allowUserToSpecifyName = allowUserToSpecifyName;

		if (domainName == null || domainName.isBlank()) {
			throw new IllegalArgumentException("Missing domain name");
		}

		String loginServer = null;
		try {
			InetSocketAddress dc = getFirstDomainController(domainName);
			loginServer = dc.getHostName();
		}
		catch (NamingException e) {
			// fall thru
		}
		if (loginServer == null) {
			throw new IllegalArgumentException("No domain controller for " + domainName);
		}

		System.setProperty("java.security.krb5.realm", domainName.toUpperCase());
		System.setProperty("java.security.krb5.kdc", loginServer);
	}

	@Override
	public String authenticate(UserManager userMgr, Subject subject, Callback[] ghidra_callbacks)
			throws LoginException {

		GhidraPrincipal principal = GhidraPrincipal.getGhidraPrincipal(subject);

		AtomicReference<String> userName = new AtomicReference<>();

		NameCallback srcNcb =
			AuthenticationModule.getFirstCallbackOfType(NameCallback.class, ghidra_callbacks);

		PasswordCallback srcPcb =
			AuthenticationModule.getFirstCallbackOfType(PasswordCallback.class, ghidra_callbacks);

		try {
			LoginContext lc = new LoginContext("", null, (loginmodule_callbacks) -> {
				// The Krb5LoginModule tends to call this callback handler multiple times.
				// Once for name, and then again for password.

				String tmpName = (allowUserToSpecifyName && srcNcb != null) ? srcNcb.getName()
						: principal.getName();
				if (stripDomainFromUsername && tmpName.contains("\\")) {
					tmpName = tmpName.replaceFirst("^.*\\\\", "");
				}

				if (tmpName == null || srcPcb == null || tmpName.isBlank()) {
					throw new IOException("Missing username or password values");
				}

				NameCallback destNcb = AuthenticationModule
						.getFirstCallbackOfType(NameCallback.class, loginmodule_callbacks);
				PasswordCallback destPcb = AuthenticationModule
						.getFirstCallbackOfType(PasswordCallback.class, loginmodule_callbacks);

				if (destNcb != null) {
					destNcb.setName(tmpName);
				}

				if (destPcb != null) {
					destPcb.setPassword(srcPcb.getPassword());
				}

				userName.set(tmpName);
			}, new JAASConfiguration("com.sun.security.auth.module.Krb5LoginModule"));

			try {
				lc.login();
			}
			catch (LoginException e) {
				// Convert plain LoginExceptions to FailedLoginExceptions to enable
				// the client to retry the login if desired.
				if (e instanceof FailedLoginException) {
					throw e;
				}
				throw new FailedLoginException(e.getMessage());
			}
		}
		finally {
			if (srcPcb != null) {
				srcPcb.clearPassword();
			}
		}

		return userName.get();
	}

	@Override
	public Callback[] getAuthenticationCallbacks() {
		return AuthenticationModule.createSimpleNamePasswordCallbacks(allowUserToSpecifyName);
	}

	@Override
	public boolean anonymousCallbacksAllowed() {
		return false;
	}

	@Override
	public boolean isNameCallbackAllowed() {
		return allowUserToSpecifyName;
	}

	//--------------------------------------------------------------------------------------------------

	/**
	 * A JAAS {@link Configuration} helper that forces a simple JAAS setup of a single
	 * 'required' {@link LoginModule}.  (instead of an external JAAS config file)
	 *
	 */
	private static class JAASConfiguration extends Configuration {

		private AppConfigurationEntry staticConfigEntry;
		private Map<String, Object> options = new HashMap<>();

		public JAASConfiguration(String loginModuleClassName) {
			staticConfigEntry = new AppConfigurationEntry(loginModuleClassName,
				AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options);
		}

		@Override
		public AppConfigurationEntry[] getAppConfigurationEntry(String name) {

			return new AppConfigurationEntry[] { staticConfigEntry };
		}

		/**
		 * Allows adding options to the {@link LoginModule}
		 *
		 * @param name string name of the option
		 * @param value value of the option
		 */
		public void addOption(String name, Object value) {
			options.put(name, value);
		}
	}

	private static final String SRV_RECORD_TYPE = "SRV";

	/**
	 * Returns the first Microsoft Active Directory domain controller for the specified domainName.
	 *
	 * @param domainName the local domain name of the MS Active Directory system
	 * @return address of the domain controller, or null if not found
	 * @throws NamingException
	 */
	private static InetSocketAddress getFirstDomainController(String domainName)
			throws NamingException {

		DirContext ctx = new InitialDirContext();

		Attributes attributes = ctx.getAttributes("dns:/_ldap._tcp.dc._msdcs." + domainName,
			new String[] { SRV_RECORD_TYPE });
		if (attributes.get(SRV_RECORD_TYPE) == null) {
			return null;
		}

		String srvRec = attributes.get(SRV_RECORD_TYPE).get().toString();

		String[] recParts = srvRec.split("\\s+", -1);

		int port = Integer.parseInt(recParts[2]);
		String host = recParts[3];

		return new InetSocketAddress(host, port);
	}

}
