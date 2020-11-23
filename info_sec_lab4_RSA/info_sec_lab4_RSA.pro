TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        debug.cpp \
        main.cpp \
        prime_number_generator.cpp \
        rsa.cpp \
        utils.cpp

HEADERS += \
    debug.h \
    prime_number_generator.h \
    rsa.h \
    utils.h
