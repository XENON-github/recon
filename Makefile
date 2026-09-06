CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread

TARGET = recon
PREFIX = /usr

SRCS = main.cpp \
       port/port-scan.cpp \
       port/service-detect.cpp \
       port/os-detect.cpp

OBJS = $(SRCS:.cpp=.o)

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

install: $(TARGET)
	install -Dm755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
