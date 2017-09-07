CC = gcc
OBJS = ini.o util.o encrypt.o
TARGET_EXE = tde_encrypt
TARGET_LIB = tde_encrypt.so

exe: clean_o $(TARGET_EXE)
lib: clean_o $(TARGET_LIB)

LDFLAGS=-L../../../build/opt/third_party/wiredtiger/ -lssl -lcrypto
$(TARGET_LIB): CFLAGS=-I. -I../../../build/opt/third_party/wiredtiger/ -I../../../src/third_party/wiredtiger/src/include/ -fPIC -shared
$(TARGET_EXE): CFLAGS=-D_UNIT_TEST_ -I. -I../../../build/opt/third_party/wiredtiger/ -I../../../src/third_party/wiredtiger/src/include/

$(TARGET_LIB): $(OBJS)
	rm -rf $(TARGET_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

$(TARGET_EXE): $(OBJS)
	rm -rf $(TARGET_EXE)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean :
	rm -rf $(TARGET_LIB) $(TARGET_EXE) *.o

clean_o :
	rm -rf *.o