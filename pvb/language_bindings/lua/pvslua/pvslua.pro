######################################################################
# generated by pvdevelop at: Mi Nov 8 11:58:45 2006
######################################################################

TEMPLATE = app
CONFIG  += USE_QT_SQL
CONFIG  -= qt
CONFIG  += warn_on release console
QT      += sql
DEFINES += LUA
DEFINES += "WINVER=0x0501"

# Input
HEADERS      += pvapp.h
SOURCES      += main.cpp                                   \
                ../../language_binding_rllib_wrap_lua.cxx  \
                ../../language_binding_wrap_lua.cxx        \
                ../../pvmain.cpp
INCLUDEPATH +=  ../..
INCLUDEPATH +=  ../lua-5.1/src/

USE_QT_SQL {
DEFINES += USE_QT_SQL
CONFIG  += qt
HEADERS      += ../../sql/qtdatabase.h
SOURCES      += ../../sql/qtdatabase.cpp
}

unix:LIBS               += ../lua-5.1/src/liblua.a
win32:LIBS              += ../lua-5.1/src/release/liblua.a

!macx {
unix:LIBS          += ../../../pvserver/libpvsmt.so -lpthread
#unix:LIBS         += ../../../pvserver/libpvsid.so
unix:INCLUDEPATH   += ../../../pvserver
unix:LIBS          += ../../../rllib/lib/librllib.so
unix:INCLUDEPATH   += ../../../rllib/lib
unix:LIBS          += -ldl
}

macx:LIBS          += ../../../pvserver/libpvsmt.a /usr/lib/libpthread.dylib
#macx:LIBS         += ../../../pvserver/libpvsid.a
macx:INCLUDEPATH   += ../../../pvserver
macx:LIBS          += ../../../rllib/lib/librllib.dylib
macx:INCLUDEPATH   += ../../../rllib/lib

win32-g++ {
QMAKE_LFLAGS       += -static-libgcc
win32:LIBS         += ../../../win-mingw/bin/librllib.a
win32:LIBS         += ../../../win-mingw/bin/libserverlib.a -lws2_32 -ladvapi32
win32:INCLUDEPATH  += ../../..//pvserver
win32:INCLUDEPATH  += ../../../rllib/lib
}

#DEFINES += USE_INETD
TARGET = pvslua
