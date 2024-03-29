/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (https://www.swig.org).
 * Version 4.1.1
 *
 * Do not make changes to this file unless you know what you are doing - modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package SWIG;

public class SBPlatformConnectOptions {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBPlatformConnectOptions(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBPlatformConnectOptions obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  protected static long swigRelease(SBPlatformConnectOptions obj) {
    long ptr = 0;
    if (obj != null) {
      if (!obj.swigCMemOwn)
        throw new RuntimeException("Cannot release ownership as memory is not owned");
      ptr = obj.swigCPtr;
      obj.swigCMemOwn = false;
      obj.delete();
    }
    return ptr;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        lldbJNI.delete_SBPlatformConnectOptions(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBPlatformConnectOptions(String url) {
    this(lldbJNI.new_SBPlatformConnectOptions__SWIG_0(url), true);
  }

  public SBPlatformConnectOptions(SBPlatformConnectOptions rhs) {
    this(lldbJNI.new_SBPlatformConnectOptions__SWIG_1(SBPlatformConnectOptions.getCPtr(rhs), rhs), true);
  }

  public String GetURL() {
    return lldbJNI.SBPlatformConnectOptions_GetURL(swigCPtr, this);
  }

  public void SetURL(String url) {
    lldbJNI.SBPlatformConnectOptions_SetURL(swigCPtr, this, url);
  }

  public boolean GetRsyncEnabled() {
    return lldbJNI.SBPlatformConnectOptions_GetRsyncEnabled(swigCPtr, this);
  }

  public void EnableRsync(String options, String remote_path_prefix, boolean omit_remote_hostname) {
    lldbJNI.SBPlatformConnectOptions_EnableRsync(swigCPtr, this, options, remote_path_prefix, omit_remote_hostname);
  }

  public void DisableRsync() {
    lldbJNI.SBPlatformConnectOptions_DisableRsync(swigCPtr, this);
  }

  public String GetLocalCacheDirectory() {
    return lldbJNI.SBPlatformConnectOptions_GetLocalCacheDirectory(swigCPtr, this);
  }

  public void SetLocalCacheDirectory(String path) {
    lldbJNI.SBPlatformConnectOptions_SetLocalCacheDirectory(swigCPtr, this, path);
  }

}
