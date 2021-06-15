/* ###
 * IP: Apache License 2.0
 */
/***
 * This is fix for a bug found in the Felix Framework:
 * 
 *   https://issues.apache.org/jira/browse/FELIX-6297
 *
 *  Because of its place on the classpath, this class overrides felix's.
 *  
 *  THIS FILE SHOULD BE REMOVED WHEN THE ISSUE IS ADDRESSED.
 *  
 *** 
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.felix.framework.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.*;
import java.util.jar.Manifest;

import org.apache.felix.framework.cache.Content;
import org.osgi.framework.Version;

public class MultiReleaseContent implements Content
{
    private final Content m_content;
    private final int m_javaVersion;

    MultiReleaseContent(int javaVersion, Content content)
    {
        m_javaVersion = javaVersion;
        m_content = content;
    }

    public static Content wrap(String javaVersionString, Content content)
    {
        int javaVersion = 8;

        try
        {
            javaVersion = Version.parseVersion(javaVersionString).getMajor();
        }
        catch (Exception ex)
        {

        }
        if (javaVersion > 8)
        {
            try
            {
                try (InputStream manifestStream = content.getEntryAsStream("META-INF/MANIFEST.MF"))
                {
                    if (manifestStream != null)
                    {
                        if ("true".equals(new Manifest(manifestStream).getMainAttributes().getValue("Multi-Release")))
                        {
                            content = new MultiReleaseContent(javaVersion, content);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
            }
        }
        return content;
    }

    @Override
    public void close()
    {
        m_content.close();
    }

    @Override
    public boolean hasEntry(String name)
    {
        return m_content.hasEntry(findPath(name));
    }

    @Override
    public Enumeration<String> getEntries()
    {
        Enumeration<String> entries = m_content.getEntries();
        if (entries != null)
        {
            Set<String> result = new LinkedHashSet<String>();
            while (entries.hasMoreElements())
            {
                String path = entries.nextElement();
                result.add(path);
                String internalPath = path;
                while (internalPath.startsWith("/"))
                {
                    internalPath = internalPath.substring(1);
                }
                if (internalPath.startsWith("META-INF/versions/") )
                {
                    int idx = internalPath.indexOf('/', "META-INF/versions/".length());
                    if ((idx != -1) && (idx + 1) < internalPath.length())
                    {
                        int version = Version.parseVersion(internalPath.substring("META-INF/versions/".length(), idx)).getMajor();
                        if ((version > 8) && (version <= m_javaVersion))
                        {
                            internalPath = internalPath.substring(idx + 1);
                            if (!internalPath.startsWith("META-INF/"))
                            {
                                result.add(internalPath);
                            }
                        }
                    }
                }
            }
            return Collections.enumeration(result);
        }
        else
        {
            return entries;
        }
    }

    @Override
    public byte[] getEntryAsBytes(String name)
    {
        return m_content.getEntryAsBytes(findPath(name));
    }

    @Override
    public InputStream getEntryAsStream(String name) throws IOException
    {
        return m_content.getEntryAsStream(findPath(name));
    }

    @Override
    public Content getEntryAsContent(String name)
    {
        return m_content.getEntryAsContent(findPath(name));
    }

    @Override
    public String getEntryAsNativeLibrary(String name)
    {
        return m_content.getEntryAsNativeLibrary(findPath(name));
    }

    @Override
    public URL getEntryAsURL(String name)
    {
        return m_content.getEntryAsURL(findPath(name));
    }

    private String findPath(String path)
    {
        String internalPath = path;
        while (internalPath.startsWith("/"))
        {
            internalPath = internalPath.substring(1);
        }
        if (!internalPath.startsWith("META-INF/"))
        {
            int version = m_javaVersion;
            while (version >= 9)
            {
                String versionPath = "META-INF/versions/" + version-- + "/" + internalPath;
                if (m_content.hasEntry(versionPath))
                {
                    return versionPath;
                }
            }
        }
        return path;
    }
}
