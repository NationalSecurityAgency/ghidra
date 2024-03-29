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

public class SBQueue {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected SBQueue(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(SBQueue obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  protected static long swigRelease(SBQueue obj) {
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
        lldbJNI.delete_SBQueue(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public SBQueue() {
    this(lldbJNI.new_SBQueue__SWIG_0(), true);
  }

  public SBQueue(SBQueue rhs) {
    this(lldbJNI.new_SBQueue__SWIG_1(SBQueue.getCPtr(rhs), rhs), true);
  }

  public boolean IsValid() {
    return lldbJNI.SBQueue_IsValid(swigCPtr, this);
  }

  public void Clear() {
    lldbJNI.SBQueue_Clear(swigCPtr, this);
  }

  public SBProcess GetProcess() {
    return new SBProcess(lldbJNI.SBQueue_GetProcess(swigCPtr, this), true);
  }

  public java.math.BigInteger GetQueueID() {
    return lldbJNI.SBQueue_GetQueueID(swigCPtr, this);
  }

  public String GetName() {
    return lldbJNI.SBQueue_GetName(swigCPtr, this);
  }

  public long GetIndexID() {
    return lldbJNI.SBQueue_GetIndexID(swigCPtr, this);
  }

  public long GetNumThreads() {
    return lldbJNI.SBQueue_GetNumThreads(swigCPtr, this);
  }

  public SBThread GetThreadAtIndex(long arg0) {
    return new SBThread(lldbJNI.SBQueue_GetThreadAtIndex(swigCPtr, this, arg0), true);
  }

  public long GetNumPendingItems() {
    return lldbJNI.SBQueue_GetNumPendingItems(swigCPtr, this);
  }

  public SBQueueItem GetPendingItemAtIndex(long arg0) {
    return new SBQueueItem(lldbJNI.SBQueue_GetPendingItemAtIndex(swigCPtr, this, arg0), true);
  }

  public long GetNumRunningItems() {
    return lldbJNI.SBQueue_GetNumRunningItems(swigCPtr, this);
  }

  public QueueKind GetKind() {
    return QueueKind.swigToEnum(lldbJNI.SBQueue_GetKind(swigCPtr, this));
  }

}
