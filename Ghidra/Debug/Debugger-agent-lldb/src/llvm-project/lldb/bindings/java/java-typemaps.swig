%include <typemaps.i>
%include <carrays.i>
%include <various.i>

%typemap(javabase) ByteArray "SWIGTYPE_p_void"
%typemap(javabody) ByteArray %{
  private long swigCPtr; // Minor bodge to work around private variable in parent
  private boolean swigCMemOwn;
  public $javaclassname(long cPtr, boolean cMemoryOwn) {
    super(cPtr, cMemoryOwn);
    this.swigCPtr = SWIGTYPE_p_void.getCPtr(this);
    swigCMemOwn = cMemoryOwn;
  }
%}

%array_class(jbyte, ByteArray);

%apply char **STRING_ARRAY { char ** }
