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

public final class DWIMPrintVerbosity {
  public final static DWIMPrintVerbosity eDWIMPrintVerbosityNone = new DWIMPrintVerbosity("eDWIMPrintVerbosityNone");
  public final static DWIMPrintVerbosity eDWIMPrintVerbosityExpression = new DWIMPrintVerbosity("eDWIMPrintVerbosityExpression");
  public final static DWIMPrintVerbosity eDWIMPrintVerbosityFull = new DWIMPrintVerbosity("eDWIMPrintVerbosityFull");

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static DWIMPrintVerbosity swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
    for (int i = 0; i < swigValues.length; i++)
      if (swigValues[i].swigValue == swigValue)
        return swigValues[i];
    throw new IllegalArgumentException("No enum " + DWIMPrintVerbosity.class + " with value " + swigValue);
  }

  private DWIMPrintVerbosity(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private DWIMPrintVerbosity(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private DWIMPrintVerbosity(String swigName, DWIMPrintVerbosity swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static DWIMPrintVerbosity[] swigValues = { eDWIMPrintVerbosityNone, eDWIMPrintVerbosityExpression, eDWIMPrintVerbosityFull };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

