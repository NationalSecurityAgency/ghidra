
BUILDDIR=html

Decompiler.html:	decompileplugin.xml
	rm -rf ${BUILDDIR}
	mkdir ${BUILDDIR}
	mkdir ${BUILDDIR}/images
	cp ../../../src/main/help/help/shared/Frontpage.css ${BUILDDIR}
	cp ../../../src/main/help/help/shared/languages.css ${BUILDDIR}
	cp ../../../src/main/help/help/topics/DecompilePlugin/images/DecompWindow.png ${BUILDDIR}/images
	cp ../../../src/main/help/help/topics/DecompilePlugin/images/EditFunctionSignature.png ${BUILDDIR}/images
	cp ../../../src/main/help/help/topics/DecompilePlugin/images/ForwardSlice.png ${BUILDDIR}/images
	cp ../../../src/main/help/help/topics/DecompilePlugin/images/decompileFunction.gif ${BUILDDIR}/images
	cp ../../../src/main/help/help/topics/DecompilePlugin/images/page_edit.png ${BUILDDIR}/images
	cp ../../../../Base/src/main/help/help/topics/Snapshots/images/camera-photo.png ${BUILDDIR}/images
	cp ../../../../Base/src/main/help/help/topics/ClipboardPlugin/images/page_white_copy.png ${BUILDDIR}/images
	cp ../../../../../Framework/Generic/src/main/resources/images/reload3.png ${BUILDDIR}/images
	cp ../../../src/main/help/help/shared/note.png ${BUILDDIR}/images
	xsltproc --stringparam base.dir ${BUILDDIR} --stringparam root.filename Decompiler decompileplugin_html.xsl decompileplugin.xml
	sed -i -e '/Frontpage.css/ { p; s/Frontpage.css/languages.css/; }' ${BUILDDIR}/*.html
