CLIENT	:= tftpClient
SERVER	:= tftpServer

CC		:= gcc
CFLAGS 	:= -O2 -Wall
.PHONY : all clean

# --- Build -------------------------------------
all: $(CLIENT) $(SERVER)

$(CLIENT) : $(CLIENT).c
	$(CC) -o $@ $^ $(CFLAGS)

$(SERVER) : $(SERVER).c
	$(CC) -o $@ $^ $(CFLAGS)

clean: 
	rm $(CLIENT) $(SERVER)


